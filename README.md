# Assembly SBOM

Generates [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs) that describe the actual contents of Maven distribution archives. Unlike the [cyclonedx-maven-plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin), which reads the Maven dependency tree, this project analyzes what is physically inside an archive:

- **Content-based identification** — every file in the archive is hashed and matched against known Maven artifacts, so the SBOM reflects exactly what ships, not what was declared.
- **Non-artifact tracking** — config files, scripts, and other non-Maven content appear as `file` components so nothing is invisible.
- **Unpacked archive awareness** — unpacked WARs, shaded JARs, and nested dependencies are detected and modeled with proper nesting.
- **Multi-ecosystem merging** — CycloneDX SBOMs from npm, pnpm, or other ecosystems can be merged into a single distribution SBOM.

**When to use which:** Use the assembly handler when you ship a distribution archive assembled by the Maven Assembly Plugin and need the SBOM to reflect exactly what is inside that archive. Use [cyclonedx-maven-plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) when you need a dependency-level SBOM for a Maven module (e.g., a library JAR published to a repository), want aggregate BOMs across a multi-module reactor, or need scope-level control over which dependencies appear in the BOM. Use both when you publish library artifacts with dependency SBOMs _and_ ship distribution archives that need content-accurate SBOMs.

The project includes two SBOM generators:

- **[Assembly Handler](#assembly-handler)** (`assembly-sbom-handler`) — a `ContainerDescriptorHandler` that plugs into the [Maven Assembly Plugin](https://maven.apache.org/plugins/maven-assembly-plugin/) and generates an SBOM automatically during archive creation.
- **[Maven Plugin](#maven-plugin)** (`assembly-sbom-maven-plugin`) — a standalone Maven plugin with a `generate` goal for scanning exploded directories (e.g., an exploded WAR) and a `merge` goal for combining multiple CycloneDX SBOMs.

## Assembly Handler

### Quick Start

#### 1. Add the handler as a plugin dependency

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-assembly-plugin</artifactId>
    <version>3.8.0</version>
    <dependencies>
        <dependency>
            <groupId>io.github.cyberstamp.maven.assembly.sbom</groupId>
            <artifactId>assembly-sbom-handler</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>
    </dependencies>
    <!-- executions... -->
</plugin>
```

#### 2. Reference the handler in your assembly descriptor

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

#### 3. Build

```
mvn package
```

The SBOM is embedded in the archive at `bom.cdx.json` (inside the base directory if one is configured).

### Example Output

The generated SBOM describes every file in the archive. Maven artifacts are identified as `library` components with Package URLs and license information. Non-artifact files appear as `file` components. Both include `evidence/occurrences` recording where they appear in the archive:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example",
      "name": "my-app",
      "version": "1.0",
      "purl": "pkg:maven/com.example/my-app@1.0?type=zip&classifier=dist",
      "hashes": [{ "alg": "SHA-256", "content": "e4f90..." }]
    }
  },
  "components": [
    {
      "type": "library",
      "group": "org.apache.commons",
      "name": "commons-lang3",
      "version": "3.17.0",
      "purl": "pkg:maven/org.apache.commons/commons-lang3@3.17.0?type=jar",
      "licenses": [{ "license": { "id": "Apache-2.0" } }],
      "hashes": [{ "alg": "SHA-256", "content": "dfc18..." }],
      "evidence": {
        "occurrences": [{ "location": "lib/commons-lang3-3.17.0.jar" }],
        "identity": [{ "field": "purl", "confidence": 1, "methods": [{ "technique": "manifest-analysis" }] }]
      }
    },
    {
      "type": "file",
      "name": "start.sh",
      "purl": "pkg:generic/start.sh?checksum=sha256:a1b2c3...",
      "hashes": [{ "alg": "SHA-256", "content": "a1b2c3..." }],
      "evidence": {
        "occurrences": [{ "location": "bin/start.sh" }]
      }
    }
  ]
}
```

### Configuration Options

Options are set inside the `<containerDescriptorHandler>` block in the assembly descriptor using `<configuration>`:

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <outputMode>external</outputMode>
    </configuration>
</containerDescriptorHandler>
```

| Option | Default | Description |
|---|---|---|
| `format` | `json` | Output format: `json` or `xml` |
| `outputPath` | `bom.cdx.json` | Filename (or relative path) of the BOM inside the archive. Only effective when `outputMode` includes `embedded` |
| `outputMode` | `embedded` | Where to write the BOM: `embedded` (inside the archive), `external` (next to the archive file, e.g., `myapp-1.0-dist.zip.cdx.json`), or `all` (both) |
| `prettyPrint` | `false` | When `true`, the JSON output is indented for readability. Has no effect on XML (always indented) |
| `failOnMissingLicense` | `false` | When `true`, the build fails if any library component has no license information in its POM |
| `hashAlgorithm` | `SHA-256` | The hash algorithm used for content hashes. Must be supported by both `java.security.MessageDigest` and the [CycloneDX specification](https://cyclonedx.org/docs/1.6/json/#hash-alg) (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3) |
| `failOnDuplicateHash` | `true` | When `true`, the build fails if two distinct artifacts have identical content hashes. Set to `false` to log a warning instead |
| `embeddedSboms` | `merge` | How to handle CycloneDX SBOM files (`.cdx.json`, `.cdx.xml`) found inside the archive: `merge` (import components as nested sub-components of the containing artifact), `link` (add an external reference of type `bom` to the containing artifact), or `ignore` |
| `externalSboms` | _(none)_ | Comma-separated list of file paths to external CycloneDX SBOMs to merge into the distribution SBOM. Relative paths are resolved against the project base directory. External SBOM component hashes also participate in archive entry matching |
| `librariesOnly` | `false` | When `true`, generic file components are removed from the generated SBOM, keeping only library components (Maven, npm, etc.). Filtering is applied after embedded and external SBOMs have been merged, so files recognized as libraries by those SBOMs are retained |
| `attach` | `false` | When `true`, the generated SBOM is attached to the Maven project as an artifact. The attached artifact has the same groupId, artifactId, classifier, and version as the distribution archive but a different type (`cdx.json` or `cdx.xml`). Requires `outputMode` to be `external` or `all`. If the Maven Assembly Plugin's own `attach` is `false`, the SBOM is not attached either |

The generator reads `includeBaseDirectory` from the assembly descriptor. When it is `true`, the base directory prefix is stripped from file paths in the BOM.

### Output Location

By default (`outputMode=embedded`), the BOM is embedded inside the archive alongside the other assembly content. If the assembly uses `<includeBaseDirectory>true</includeBaseDirectory>`, the BOM is placed inside the base directory.

Setting `outputMode` to `external` writes the BOM as a separate file next to the archive, named after the archive with a `.cdx.json` (or `.cdx.xml`) suffix. When the BOM is external, the main component is updated with the SHA-256 hash of the archive after it is written. This is useful for CI pipelines that consume the BOM separately.

Setting `outputMode` to `all` produces both an embedded and an external BOM.

#### Attaching the SBOM as a Maven Artifact

Setting `attach` to `true` registers the external BOM as an attached Maven project artifact. This means the SBOM is installed to the local repository and deployed to remote repositories alongside the distribution archive. The attached artifact uses type `cdx.json` (or `cdx.xml`) and the same classifier as the distribution archive, so for a distribution attached as `myapp-1.0-dist.zip`, the SBOM is installed as `myapp-1.0-dist.cdx.json`.

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <outputMode>external</outputMode>
        <attach>true</attach>
    </configuration>
</containerDescriptorHandler>
```

### Features

#### Artifact Identification

Every file in the assembly is inspected and classified as either a **library** (Maven artifact) or a **file** (non-artifact):

- **Content hash matching** — each archive entry's content hash is computed and looked up against a pre-built index of the project's resolved Maven artifacts. This identifies artifacts reliably regardless of filename (e.g., custom `outputFileNameMapping` in the assembly descriptor).
- **Deduplication** — if the same artifact appears at multiple locations in the archive, it is represented as a single component with multiple `evidence/occurrence` entries.

Library components include full [Package URL](https://github.com/package-url/purl-spec) (PURL) identifiers:

```
pkg:maven/org.apache.commons/commons-io@2.22.0?type=jar
```

#### License Resolution

The generator resolves licenses for every Maven artifact component by reading the artifact's effective POM (including licenses inherited from parent POMs). License names and URLs are mapped to [SPDX](https://spdx.org/licenses/) license identifiers using the CycloneDX license database, which includes exact matches, name matching, URL matching, and fuzzy matching against common license name variants.

When no SPDX match is found, the raw license name and URL from the POM are preserved in the component. If an artifact's effective POM declares no licenses at all, a warning is logged. Set `failOnMissingLicense` to `true` to fail the build instead.

#### Unpacked Archive Detection

When an assembly descriptor unpacks an artifact (e.g., a WAR with `<unpack>true</unpack>`), the handler detects the unpacked content by comparing SHA-256 hashes of the artifact's internal entries against the archive entries.

- The unpacked artifact is added as a single **library** component.
- Individual files from the unpacked archive that can be identified are **not** listed as separate file components — they appear as nested **library** components.
- Files that cannot be identified remain as **file** components.
- Nested JARs within the unpacked archive (e.g., JARs in a WAR's `WEB-INF/lib/`) are identified as separate **library** components with proper Maven PURLs.

Nested JAR identification uses three strategies:

1. **Reactor module lookup** — if the unpacked artifact is a module in the current reactor build, its resolved Maven dependencies are used to identify nested JARs by content hash.
2. **Effective POM resolution** — for non-reactor artifacts, the handler builds the artifact's effective POM model and resolves its compile/runtime-scoped dependencies from the Maven repository, then matches nested JARs by content hash.
3. **`pom.properties` parsing** — as a fallback, the handler reads `META-INF/maven/**/pom.properties` from inside each nested JAR to extract Maven coordinates.

#### Shaded / Fat JAR Detection

Shaded (fat) JARs bundle their dependencies inside a single JAR file. These JARs contain multiple `META-INF/maven/**/pom.properties` entries — one for the main artifact and one for each bundled dependency.

When a nested JAR contains multiple `pom.properties` entries, the handler attempts to identify the owner by matching the JAR filename against the `artifactId` values. For example, a file named `nimbus-jose-jwt-10.6.jar` containing `pom.properties` for `nimbus-jose-jwt`, `jcip-annotations`, and `gson` would be identified as `nimbus-jose-jwt` because only that `artifactId` appears in the filename. The bundled dependencies (`jcip-annotations` and `gson`) are then registered as nested **library** components under the identified artifact.

When the filename is ambiguous (zero or multiple `artifactId` values match), the JAR appears as a **file** component with the discovered Maven artifacts nested as **library** sub-components. This preserves all available identity information without making an incorrect attribution.

#### Dependency Graph

The BOM includes a CycloneDX dependency graph reflecting the Maven dependency tree. Only artifacts that are actually present in the assembly are included.

- **Direct vs. transitive** — the graph preserves the Maven dependency hierarchy. Transitive dependencies are connected through their parent, not listed as direct dependencies of the main component.
- **Unpacked artifact dependencies** — nested JARs identified within unpacked archives are connected to their parent artifact via dependency edges.

#### SBOM Merging

Distribution archives often bundle artifacts from non-Maven ecosystems — most commonly JavaScript libraries inside WARs or JARs. The generator can detect and integrate CycloneDX SBOMs from those ecosystems, turning otherwise unidentified files into properly typed LIBRARY components with Package URLs, licenses, and dependency relationships.

##### Auto-detection

CycloneDX SBOM files (`.cdx.json` or `.cdx.xml`) are automatically detected in two places:

1. **Archive entries** — when an artifact is unpacked into the distribution (e.g., a WAR with `<unpack>true</unpack>`), any SBOM file among the unpacked content is detected. The parent is determined by the directory structure.
2. **Inside bundled JARs/WARs** — matched artifacts that are ZIP-based archives are scanned for embedded SBOM files.

When both JSON and XML variants of the same SBOM exist (same filename stem in the same directory), the JSON variant is preferred and the XML duplicate is skipped.

##### Handling modes

The `embeddedSboms` option controls what happens with detected SBOMs:

- **`merge`** (default) — the SBOM's components are imported as nested sub-components of the containing artifact. Dependency entries are imported into the distribution BOM's dependency section. No cross-ecosystem dependency edges are created — nesting already captures the containment relationship.
- **`link`** — an `externalReference` of type `bom` is added to the containing artifact, pointing to the SBOM file's location within the archive. The SBOM file remains in the archive.
- **`ignore`** — embedded SBOMs are not processed.

##### External SBOMs

The `externalSboms` option accepts a comma-separated list of file paths to CycloneDX SBOMs generated outside the Maven build (e.g., by `cdxgen`, `@cyclonedx/cyclonedx-npm`, or pnpm). These SBOMs are:

1. **Used for archive entry matching** — component hashes from external SBOMs are checked against unmatched archive entries. If a match is found, the entry is identified from the external SBOM rather than appearing as an unidentified FILE component.
2. **Merged under the main component** — all external SBOM components are nested under the distribution's main component.

Example configuration:

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <outputMode>external</outputMode>
        <externalSboms>target/js-sbom.cdx.json</externalSboms>
    </configuration>
</containerDescriptorHandler>
```

##### Generating JavaScript SBOMs

| Package Manager | Tool |
|---|---|
| npm | [`@cyclonedx/cyclonedx-npm`](https://www.npmjs.com/package/@cyclonedx/cyclonedx-npm) |
| Yarn | [`@cyclonedx/cyclonedx-node-yarn`](https://github.com/CycloneDX/cyclonedx-node-yarn) |
| pnpm | [`cdxgen`](https://www.npmjs.com/package/@cyclonedx/cdxgen) |
| Any | [`cdxgen`](https://www.npmjs.com/package/@cyclonedx/cdxgen) (multi-ecosystem) |

#### Reproducible Builds

The generator produces deterministic output for reproducible builds:

- **Serial number** — a UUID derived from the project's `groupId:artifactId:version:assemblyId`, not random.
- **Timestamp** — uses `project.build.outputTimestamp` when set (the standard Maven [reproducible builds](https://maven.apache.org/guides/mini/guide-reproducible-builds.html) property), otherwise falls back to the current time.
- **Ordering** — components and dependencies are sorted alphabetically, so identical inputs produce identical output regardless of filesystem or iteration order.

#### CycloneDX Component Types

| Component Type | When Used |
|---|---|
| `application` | The main assembly (appears in BOM metadata) |
| `library` | Maven artifacts — both packed JARs and unpacked archives. May appear as nested sub-components of other `library` or `file` components (e.g., bundled dependencies inside a shaded JAR) |
| `file` | Non-artifact files (config files, scripts, schemas, licenses, etc.) and JARs that could not be positively identified as Maven artifacts. May contain nested `library` sub-components when Maven artifacts are discovered inside (e.g., via `pom.properties` in a shaded JAR) |

The main `application` component's PURL includes the archive type derived from the output filename (e.g., `zip`, `tar.gz`) and a classifier. The classifier is determined from the assembly plugin configuration: if an explicit `<classifier>` is set it is used, otherwise the assembly descriptor id is used unless `<appendAssemblyId>` is `false`, in which case the classifier is omitted.

#### Evidence

Each component includes CycloneDX `evidence` with `occurrence` entries recording where it appears in the archive. Library components include an `identity` with technique `manifest-analysis` indicating they were identified through Maven artifact metadata.

## Maven Plugin

The `assembly-sbom-maven-plugin` provides two goals for projects that need SBOM generation outside the assembly plugin workflow.

### `generate` Goal

Scans an exploded directory (e.g., an exploded WAR produced by `maven-war-plugin`) and generates a CycloneDX SBOM by identifying Maven artifacts via content-hash matching. The same identification engine as the assembly handler is used.

```xml
<plugin>
    <groupId>io.github.cyberstamp.maven.assembly.sbom</groupId>
    <artifactId>assembly-sbom-maven-plugin</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <executions>
        <execution>
            <goals>
                <goal>generate</goal>
            </goals>
            <configuration>
                <inputDirectory>${project.build.directory}/${project.build.finalName}</inputDirectory>
            </configuration>
        </execution>
    </executions>
</plugin>
```

| Option | Default | Description |
|---|---|---|
| `inputDirectory` | `${project.build.directory}/${project.build.finalName}` | The exploded directory to scan |
| `outputFile` | `${project.build.directory}/bom.cdx.json` | Path to write the generated SBOM |
| `format` | `json` | Output format: `json` or `xml` |
| `prettyPrint` | `true` | Whether to indent the JSON output |
| `hashAlgorithm` | `SHA-256` | Hash algorithm for content hashes |
| `embeddedSboms` | `merge` | How to handle embedded CycloneDX SBOMs: `merge`, `link`, or `ignore` |
| `externalSboms` | _(none)_ | Comma-separated paths to external SBOMs to merge |
| `failOnMissingLicense` | `false` | Fail the build if any library has no license info |
| `failOnDuplicateHash` | `true` | Fail the build on duplicate artifact hashes |
| `librariesOnly` | `false` | Exclude generic file components from the output |
| `attach` | `false` | Attach the generated SBOM to the Maven project as an artifact with type `cdx.json` or `cdx.xml` and classifier `cyclonedx` |

### `merge` Goal

Combines multiple CycloneDX SBOMs into a single BOM. This is useful when a project bundles components from multiple ecosystems (e.g., Maven + npm) and you need a unified SBOM.

```xml
<plugin>
    <groupId>io.github.cyberstamp.maven.assembly.sbom</groupId>
    <artifactId>assembly-sbom-maven-plugin</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <executions>
        <execution>
            <goals>
                <goal>merge</goal>
            </goals>
            <configuration>
                <baseSbom>${project.build.directory}/bom.json</baseSbom>
                <externalSboms>
                    <externalSbom>path/to/js-bom.cdx.json</externalSbom>
                </externalSboms>
                <outputFile>${project.build.directory}/merged-bom.cdx.json</outputFile>
            </configuration>
        </execution>
    </executions>
</plugin>
```

| Option | Default | Description |
|---|---|---|
| `baseSbom` | _(required)_ | Path to the base SBOM file (e.g., the Maven-generated BOM) |
| `externalSboms` | _(required)_ | List of external SBOM files to merge into the base BOM |
| `outputFile` | `${project.build.directory}/merged-bom.cdx.json` | Path to write the merged BOM |
| `format` | `json` | Output format: `json` or `xml` |
| `prettyPrint` | `true` | Whether to indent the JSON output |
| `nested` | `false` | When `false`, external components are added as top-level components (flat merge). When `true`, they are nested as sub-components of the parent component |
| `parentBomRef` | _(auto-detected)_ | Only used when `nested` is `true`. The `bom-ref` of the component to nest external components under. Defaults to the base BOM's `metadata.component.bomRef` |

By default, external SBOM components are added as top-level components alongside the base BOM's components (flat merge). This is appropriate when the external components are peers of the base components (e.g., npm dependencies alongside Maven dependencies in a WAR). Set `nested` to `true` to nest them as sub-components of the parent component instead, which is appropriate when the external SBOM describes contents _inside_ a specific artifact. Dependency entries from external SBOMs are always imported into the merged BOM's dependency section.

## Requirements

- Java 17+
- Maven 3.9+
- Maven Assembly Plugin 3.8.0+ (for the handler)

## Project Structure

| Module | ArtifactId | Description |
|---|---|---|
| [core](core/) | `assembly-sbom-core` | Core SBOM generation engine — archive analysis, component identification, BOM building and merging |
| [handler](handler/) | `assembly-sbom-handler` | `ContainerDescriptorHandler` for the Maven Assembly Plugin — delegates to `assembly-sbom-core` |
| [maven-plugin](maven-plugin/) | `assembly-sbom-maven-plugin` | Maven plugin with `generate` and `merge` goals |
