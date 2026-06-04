# Assembly CycloneDX SBOM Generator

Generates a [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (SBOM) for archives produced by the [Maven Assembly Plugin](https://maven.apache.org/plugins/maven-assembly-plugin/).

The generator inspects every file being packaged into the assembly, identifies Maven artifacts, builds a dependency graph, and produces a CycloneDX 1.6 BOM in JSON or XML format. The result is a complete inventory of the assembly's contents — which libraries are included, where they came from, and how they relate to each other.

Implemented as a `ContainerDescriptorHandler`, it hooks into the assembly plugin's archive creation lifecycle and runs automatically as part of `mvn package`.

## Quick Start

### 1. Add the handler as a plugin dependency

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-assembly-plugin</artifactId>
    <version>3.8.0</version>
    <dependencies>
        <dependency>
            <groupId>io.github.aloubyansky.maven.assembly.sbom</groupId>
            <artifactId>maven-assembly-cyclonedx</artifactId>
            <version>1.0-SNAPSHOT</version>
        </dependency>
    </dependencies>
    <!-- executions... -->
</plugin>
```

### 2. Reference the handler in your assembly descriptor

```xml
<assembly xmlns="http://maven.apache.org/ASSEMBLY/2.2.0">
    <id>dist</id>
    <formats>
        <format>zip</format>
    </formats>
    <includeBaseDirectory>true</includeBaseDirectory>

    <containerDescriptorHandlers>
        <containerDescriptorHandler>
            <handlerName>sbom</handlerName>
        </containerDescriptorHandler>
    </containerDescriptorHandlers>

    <!-- fileSets, dependencySets, etc. -->
</assembly>
```

### 3. Build

```
mvn package
```

The SBOM is embedded in the archive at `bom.cdx.json` (inside the base directory if one is configured).

## Configuration Options

Options are set inside the `<containerDescriptorHandler>` block in the assembly descriptor using `<configuration>`:

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <output>external</output>
    </configuration>
</containerDescriptorHandler>
```

| Option | Default | Description |
|---|---|---|
| `format` | `json` | Output format: `json` or `xml` |
| `outputPath` | `bom.cdx.json` | Filename (or relative path) of the generated BOM when embedded |
| `output` | `embedded` | Where to write the BOM: `embedded` (inside the archive), `external` (next to the archive file, e.g., `myapp-1.0-dist.zip.cdx.json`), or `all` (both) |
| `prettyPrint` | `false` | When `true`, the JSON output is indented for readability. Has no effect on XML (always indented) |
| `failOnMissingLicense` | `false` | When `true`, the build fails if any library component has no license information in its POM |
| `hashAlgorithm` | `SHA-256` | The hash algorithm used for content hashes. Must be supported by both `java.security.MessageDigest` and the [CycloneDX specification](https://cyclonedx.org/docs/1.6/json/#hash-alg) (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3) |
| `failOnDuplicateHash` | `true` | When `true`, the build fails if two distinct artifacts have identical content hashes. Set to `false` to log a warning instead |

The generator reads `includeBaseDirectory` from the assembly descriptor. When it is `true`, the base directory prefix is stripped from file paths in the BOM.

### Output Location

By default (`output=embedded`), the BOM is embedded inside the archive alongside the other assembly content. If the assembly uses `<includeBaseDirectory>true</includeBaseDirectory>`, the BOM is placed inside the base directory.

Setting `output` to `external` writes the BOM as a separate file next to the archive, named after the archive with a `.cdx.json` (or `.cdx.xml`) suffix. When the BOM is external, the main component is updated with the SHA-256 hash of the archive after it is written. This is useful for CI pipelines that consume the BOM separately.

Setting `output` to `all` produces both an embedded and an external BOM.

## Features

### License Resolution

The generator resolves licenses for every Maven artifact component by reading the artifact's effective POM (including licenses inherited from parent POMs). License names and URLs are mapped to [SPDX](https://spdx.org/licenses/) license identifiers using the CycloneDX license database, which includes exact matches, name matching, URL matching, and fuzzy matching against common license name variants.

When no SPDX match is found, the raw license name and URL from the POM are preserved in the component. If an artifact's effective POM declares no licenses at all, a warning is logged. Set `failOnMissingLicense` to `true` to fail the build instead.

### Artifact Identification

Every file in the assembly is inspected and classified as either a **library** (Maven artifact) or a **file** (non-artifact):

- **Content hash matching** — each archive entry's content hash is computed and looked up against a pre-built index of the project's resolved Maven artifacts. This identifies artifacts reliably regardless of filename (e.g., custom `outputFileNameMapping` in the assembly descriptor).
- **Deduplication** — if the same artifact appears at multiple locations in the archive, it is represented as a single component with multiple `evidence/occurrence` entries.

Library components include full [Package URL](https://github.com/package-url/purl-spec) (PURL) identifiers:

```
pkg:maven/org.apache.commons/commons-io@2.22.0?type=jar
```

### Unpacked Archive Detection

When an assembly descriptor unpacks an artifact (e.g., a WAR with `<unpack>true</unpack>`), the handler detects the unpacked content by comparing SHA-256 hashes of the artifact's internal entries against the archive entries.

- The unpacked artifact is added as a single **library** component.
- Individual files from the unpacked archive are **not** listed as separate file components.
- Nested JARs within the unpacked archive (e.g., JARs in a WAR's `WEB-INF/lib/`) are identified as separate **library** components with proper Maven PURLs.

Nested JAR identification uses three strategies:

1. **Reactor module lookup** — if the unpacked artifact is a module in the current reactor build, its resolved Maven dependencies are used to identify nested JARs by content hash.
2. **Effective POM resolution** — for non-reactor artifacts, the handler builds the artifact's effective POM model and resolves its compile/runtime-scoped dependencies from the Maven repository, then matches nested JARs by content hash.
3. **`pom.properties` parsing** — as a fallback, the handler reads `META-INF/maven/**/pom.properties` from inside each nested JAR to extract Maven coordinates.

### Dependency Graph

The BOM includes a CycloneDX dependency graph reflecting the Maven dependency tree. Only artifacts that are actually present in the assembly are included.

- **Direct vs. transitive** — the graph preserves the Maven dependency hierarchy. Transitive dependencies are connected through their parent, not listed as direct dependencies of the main component.
- **Unpacked artifact dependencies** — nested JARs identified within unpacked archives are connected to their parent artifact via dependency edges.

### Reproducible Builds

The generator produces deterministic output for reproducible builds:

- **Serial number** — a UUID derived from the project's `groupId:artifactId:version:assemblyId`, not random.
- **Timestamp** — uses `project.build.outputTimestamp` when set (the standard Maven [reproducible builds](https://maven.apache.org/guides/mini/guide-reproducible-builds.html) property), otherwise falls back to the current time.
- **Ordering** — components and dependencies are sorted alphabetically, so identical inputs produce identical output regardless of filesystem or iteration order.

### CycloneDX Component Types

| Component Type | When Used |
|---|---|
| `application` | The main assembly (appears in BOM metadata) |
| `library` | Maven artifacts — both packed JARs and unpacked archives |
| `file` | Non-artifact files (config files, scripts, schemas, licenses, etc.) |

The main `application` component's PURL includes the archive type derived from the output filename (e.g., `zip`, `tar.gz`) and a classifier. The classifier is determined from the assembly plugin configuration: if an explicit `<classifier>` is set it is used, otherwise the assembly descriptor id is used unless `<appendAssemblyId>` is `false`, in which case the classifier is omitted.

### Evidence

Each component includes CycloneDX `evidence` with `occurrence` entries recording where it appears in the archive. Library components include an `identity` with technique `manifest-analysis` indicating they were identified through Maven artifact metadata.

## Comparison with cyclonedx-maven-plugin

The [cyclonedx-maven-plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) is the official CycloneDX tool for Maven projects. It generates SBOMs by reading the Maven dependency tree. This project takes a different approach — it analyzes the actual contents of an assembly archive. The two tools serve complementary purposes.

| | Assembly CycloneDX | cyclonedx-maven-plugin |
|---|---|---|
| **What it describes** | A distribution archive (ZIP, TAR, etc.) produced by the Maven Assembly Plugin | A Maven module and its resolved dependencies |
| **How it identifies components** | Computes content hashes of every file in the archive and matches them against known Maven artifacts | Reads the Maven dependency tree (`compile`, `runtime`, `provided`, etc. scopes) |
| **Scope accuracy** | Only includes what is physically present in the archive — no more, no less | Includes all resolved dependencies for configured scopes, even if they are excluded from the final distribution |
| **Unpacked archives** | Detects unpacked WARs/JARs by matching internal entry hashes; identifies nested JARs within them | No archive content analysis — operates on declared dependencies only |
| **Non-artifact files** | Tracks config files, scripts, and other non-Maven content as `file` components | Not applicable — only tracks Maven dependencies |
| **Dependency graph** | Reflects the subset of the Maven dependency tree actually present in the archive | Reflects the full Maven dependency tree for configured scopes |
| **BOM placement** | Embedded inside the archive, written externally alongside it, or both | Attached as a separate Maven artifact with a `cyclonedx` classifier |
| **Deduplication** | Same artifact at multiple archive paths → single component with multiple `evidence/occurrence` entries | Not applicable (no archive paths) |
| **Multi-module support** | One BOM per assembly | Per-module BOMs, aggregate BOMs across the reactor, and package-specific BOMs (`war`/`ear`) |
| **Integration point** | `ContainerDescriptorHandler` — runs automatically during `mvn package` as part of the assembly plugin | Standalone plugin goals (`makeBom`, `makeAggregateBom`, `makePackageBom`) |

### When to use which

**Use this project** when you ship a distribution archive assembled by the Maven Assembly Plugin and need the SBOM to reflect exactly what is inside that archive — including unpacked content, nested JARs, and non-artifact files.

**Use cyclonedx-maven-plugin** when you need a dependency-level SBOM for a Maven module (e.g., a library JAR published to a repository), want aggregate BOMs across a multi-module reactor, or need scope-level control over which dependencies appear in the BOM.

**Use both** when you publish library artifacts with dependency SBOMs _and_ ship distribution archives that need content-accurate SBOMs.

## Requirements

- Java 17+
- Maven Assembly Plugin 3.8.0+
- Maven 3.9+

## Example Output

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2026-05-08T09:00:00Z",
    "component": {
      "type": "application",
      "group": "com.example",
      "name": "my-app",
      "version": "1.0",
      "purl": "pkg:maven/com.example/my-app@1.0?type=zip&classifier=dist"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "org.apache.commons",
      "name": "commons-io",
      "version": "2.22.0",
      "purl": "pkg:maven/org.apache.commons/commons-io@2.22.0?type=jar",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "hashes": [{"alg": "SHA-256", "content": "abcdef..."}],
      "evidence": {
        "occurrences": [{"location": "lib/commons-io-2.22.0.jar"}]
      }
    }
  ],
  "dependencies": [
    {"ref": "pkg:maven/com.example/my-app@1.0?type=zip&classifier=dist", "dependsOn": ["pkg:maven/org.apache.commons/commons-io@2.22.0?type=jar"]}
  ]
}
```

