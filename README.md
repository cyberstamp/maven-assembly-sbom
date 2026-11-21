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

## Contents

- [Assembly Handler](#assembly-handler)
  - [Quick Start](#quick-start)
  - [Example Output](#example-output)
  - [Configuration Options](#configuration-options)
  - [Output Location](#output-location)
- [Maven Plugin](#maven-plugin)
  - [`generate` Goal](#generate-goal)
  - [`merge` Goal](#merge-goal)
- [How It Works](#how-it-works)
  - [Artifact Identification](#artifact-identification)
  - [License Resolution](#license-resolution)
  - [Unpacked Archive Detection](#unpacked-archive-detection)
  - [Shaded / Fat JAR Detection](#shaded--fat-jar-detection)
  - [Dependency Graph](#dependency-graph)
  - [SBOM Merging](#sbom-merging)
  - [Cryptography Bills of Materials (CBOM)](#cryptography-bills-of-materials-cbom)
  - [Reproducible Builds](#reproducible-builds)
  - [CycloneDX Component Types](#cyclonedx-component-types)
  - [Evidence](#evidence)
- [Requirements](#requirements)
- [Project Structure](#project-structure)

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
            <groupId>dev.cyberstamp.maven.assembly.sbom</groupId>
            <artifactId>assembly-sbom-handler</artifactId>
            <version>0.1.10</version>
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
  "specVersion": "1.7",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example",
      "name": "my-app",
      "version": "1.0",
      "purl": "pkg:maven/com.example/my-app@1.0?classifier=dist&type=zip",
      "hashes": [{ "alg": "SHA-256", "content": "e4f90..." }]
    }
  },
  "components": [
    {
      "type": "library",
      "group": "org.apache.commons",
      "name": "commons-lang3",
      "version": "3.17.0",
      "purl": "pkg:maven/org.apache.commons/commons-lang3@3.17.0",
      "licenses": [{ "license": { "id": "Apache-2.0" } }],
      "hashes": [{ "alg": "SHA-256", "content": "dfc18..." }],
      "evidence": {
        "occurrences": [{ "location": "lib/commons-lang3-3.17.0.jar" }],
        "identity": [{ "field": "purl", "confidence": 1.0, "methods": [{ "technique": "hash-comparison", "confidence": 1.0 }] }]
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
| `identityEvidence` | `true` | When `true`, components this tool identifies carry identity evidence (see [Evidence](#evidence)). Set to `false` to emit none of its own; identity from external or embedded SBOMs is preserved |
| `embeddedSboms` | `merge` | How to handle CycloneDX SBOM files (`.cdx.json`, `.cdx.xml`) found inside the archive: `merge` (import components as nested sub-components of the containing artifact), `link` (add an external reference of type `bom` to the containing artifact), or `ignore` |
| `externalSboms` | _(none)_ | Comma-separated list of file paths to external CycloneDX SBOMs to merge into the distribution SBOM. Relative paths are resolved against the project base directory. External SBOM component hashes also participate in archive entry matching |
| `librariesOnly` | `false` | When `true`, generic file components are removed from the generated SBOM, keeping only library components (Maven, npm, etc.). Filtering is applied after embedded and external SBOMs have been merged, so files recognized as libraries by those SBOMs are retained |
| `attach` | `false` | When `true`, the generated SBOM is attached to the Maven project as an artifact. The attached artifact has the same groupId, artifactId, classifier, and version as the distribution archive and an artifact type encoding the archive format and SBOM format (e.g. `zip.cdx.json`, `tar.gz.cdx.json`, `zip.cdx.xml`). Requires `outputMode` to be `external` or `all`. If the Maven Assembly Plugin's own `attach` is `false`, the SBOM is not attached either |
| `schemaVersion` | _(latest)_ | CycloneDX schema version to use for SBOM output and serial-number computation, e.g. `1.5` or `1.6`. Defaults to the latest version supported by the integrated CycloneDX Java library |
| `product` | _(none)_ | User-configurable metadata for the main BOM component. See [Product](#product) below |
| `mavenArtifactMatchers` | _(none)_ | Ordered list of matchers (`<central/>`, `<nexus>`, `<artifactory>`) that identify non-Maven-built jars (Gradle, Ant, ...) by their SHA-1. See [Maven Artifact Matchers](#maven-artifact-matchers) below |

The generator reads `includeBaseDirectory` from the assembly descriptor. When it is `true`, the base directory prefix is stripped from file paths in the BOM.

#### Product

The `product` element sets additional metadata on the main BOM component that cannot be derived from Maven project coordinates:

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <product>
            <cpe>cpe:2.3:a:example:myapp:1.0:*:*:*:*:*:*:*</cpe>
            <description>My application distribution</description>
            <supplier>
                <name>Acme Corp</name>
                <url>https://acme.com</url>
            </supplier>
            <manufacturer>
                <name>Acme Manufacturing</name>
                <url>https://manufacturing.acme.com</url>
            </manufacturer>
            <publisher>Acme Corp</publisher>
            <copyright>Copyright 2026 Acme Corp</copyright>
        </product>
    </configuration>
</containerDescriptorHandler>
```

| Field | Description |
|---|---|
| `cpe` | [CPE](https://nvd.nist.gov/products/cpe) 2.2 or 2.3 identifier |
| `description` | Free-text description |
| `supplier/name`, `supplier/url` | Organization that supplied the component |
| `manufacturer/name`, `manufacturer/url` | Organization that manufactured the component |
| `publisher` | Publisher name |
| `copyright` | Copyright text |

All fields are optional. The same `product` element is available on the [`generate` goal](#generate-goal).

#### Maven Artifact Matchers

Projects that assemble artifacts built with Gradle, Ant, or anything other than Maven have no `pom.properties` or resolvable Maven dependency for those files, so they end up as generic `file` components (`pkg:generic/...`) rather than `library` components (`pkg:maven/...`). `mavenArtifactMatchers` closes that gap: for files that remain unidentified after every other (local, offline) technique, it looks up their SHA-1 content hash against Maven Central and/or an internal Nexus or Artifactory, and promotes a hit to a proper Maven `library` component.

Matchers only ever run as a last resort, after hash matching, unpacked-archive detection, embedded `pom.properties`, and external SBOM matching have all had their chance. None is configured by default, so no artifact checksum ever leaves the build unless you explicitly say where it should go. Remote matchers are skipped with a warning when Maven runs in offline mode (`-o`).

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <mavenArtifactMatchers>
            <nexus>
                <url>https://nexus.example.com/service/rest/v1/search?sha1={sha1}&amp;repository=internal</url>
                <serverId>my-nexus</serverId>
            </nexus>
            <central/>
            <artifactory>
                <url>https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}</url>
                <serverId>my-artifactory</serverId>
                <excludes>
                    <exclude>**/internal-*.jar</exclude>
                </excludes>
            </artifactory>
        </mavenArtifactMatchers>
    </configuration>
</containerDescriptorHandler>
```

Each element enables one matcher: `<central/>` for the public Maven Central search API, `<nexus>` for a Nexus Repository Manager **3** instance, and `<artifactory>` for a JFrog Artifactory instance. Matchers are tried in the order they are listed, stopping at the first match. `<nexus>` and `<artifactory>` may be listed more than once, e.g. for several internal instances; `<central/>` at most once.

| Field | Applies to | Default | Description |
|---|---|---|---|
| `url` | all | _(none)_; built-in `search.maven.org` URL for `<central/>` | Complete search URL with a literal `{sha1}` in place of the content hash. Required for `<nexus>` and `<artifactory>`. See [Writing the search URL](#writing-the-search-url) below |
| `serverId` | `<nexus>`, `<artifactory>` | _(none)_ | Id of a `<server>` in `settings.xml` whose username/password are sent as HTTP Basic auth. Omit for anonymous access |
| `includes` | all | `*.jar`, `**/*.jar` | Glob patterns (matched against the archive-relative path) selecting which unmatched files this matcher is offered. Note that `**/*.jar` alone does not match JARs at the archive root, hence the separate `*.jar` |
| `excludes` | all | _(none)_ | Glob patterns excluding otherwise-included files |
| `timeoutMillis` | all | `3000` | Per-request timeout |
| `maxLookups` | all | `200` | Hard cap on the number of lookups this matcher performs in a single run. Exceeding it **fails the build** with a clear error. Raise it, or narrow `includes`/`excludes`, if a build legitimately needs more lookups |

Credentials are never written into the POM: `serverId` references a `<server>` entry in `settings.xml` (optionally with an encrypted password, like any other Maven credential), resolved at build time. An invalid configuration, such as a missing `url` or a `url` without `{sha1}`, fails the build. The same `mavenArtifactMatchers` element is available on the [`generate` goal](#generate-goal).

##### How coordinates are determined

A matcher only reports a match when the repository knows a file with exactly the same SHA-1, so it finds files whose bytes were published as-is (typically third-party libraries), not ones rebuilt locally. How the coordinates are read from the answer, and the resulting identity confidence, differs per repository:

- **Nexus** reports the coordinates of the matching asset, including its classifier and extension, from the asset's own recorded metadata (confidence `1.0`). If no asset carries a matching checksum, the first component's group, name and version are used without a classifier (confidence `0.9`, or lower if several components share the hash — see below).
- **Artifactory** only reports the path of matching files; candidates are tried in order until one follows the standard Maven repository layout (a file name starting with `<artifactId>-<version>`), skipping e.g. results from a `generic` repository. The classifier and extension come from a file name of the form `<artifactId>-<version>[-<classifier>].<extension>`, including timestamped snapshots — best-effort, since it is a local heuristic rather than recorded metadata, so always confidence `0.9`.
- **Maven Central**'s search API does not say which file of an artifact matched. A classifier is derived from the archive entry's own file name, but only trusted if confirmed by Central's `ec` ("extra content") list of file suffixes published for that version; otherwise the match falls back to the bare group/artifact/version. Always confidence `0.9`.

The confidence value reflects how directly the match is backed by the repository's own data: `1.0` when a repository returns per-file metadata for the exact matching content (a local hash match, or Nexus's asset match); `0.9` as the default for a remote match with no per-file confirmation; and `1/n` when `n` distinct components share the same content hash with no way to prefer one, splitting confidence evenly across them.

##### Writing the search URL

`url` takes the **complete search request**, not just a server address. Write it exactly as you'd call it with `curl`, but with a literal `{sha1}` where the content hash goes. At lookup time, the plugin only substitutes `{sha1}` with the actual hash and calls the URL as-is; it never builds or guesses any part of the request itself. Maven Central has a working default, so its `url` is purely an optional override.

```xml
<!-- Nexus 3: GET /service/rest/v1/search?sha1=... -->
<nexus>
    <url>https://nexus.example.com/service/rest/v1/search?sha1={sha1}</url>
</nexus>

<!-- Artifactory: GET /api/search/checksum?sha1=... -->
<artifactory>
    <url>https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}</url>
</artifactory>

<!-- Maven Central: optional, overrides the built-in search.maven.org default -->
<central>
    <url>https://repo.example.com/central-mirror/solrsearch/select?q=1:{sha1}&amp;rows=1&amp;wt=json</url>
</central>
```

Official API reference for each backend's own query parameters (e.g. Nexus's `repository` filter, Artifactory's `repos` filter):

- Maven Central: [Central REST API guide](https://central.sonatype.org/search/rest-api-guide/)
- Nexus Repository 3: [Search API](https://help.sonatype.com/en/search-api.html)
- JFrog Artifactory: [Checksum Search](https://docs.jfrog.com/artifactory/reference/searchChecksum)

This is deliberate, for two reasons:
1. **You can add any extra query parameter your server supports**, like Nexus's `repository` filter or Artifactory's `repos` filter, to restrict the search to specific (groups of) repositories. Just append it to the URL yourself:
   ```xml
   <url>https://nexus.example.com/service/rest/v1/search?sha1={sha1}&amp;repository=my-repo</url>
   <url>https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}&amp;repos=central,my-internal-repo</url>
   ```
2. **It's resilient to future API changes.** If Nexus, Artifactory, or Sonatype ever changes its REST path or parameter names, you only need to update this one setting, not wait for a new release of this plugin. That's also why `<central/>` accepts a `url` despite needing no configuration normally: it lets you point at an internal mirror of the Central search API, or adapt in place if the public one ever changes shape.

### Output Location

By default (`outputMode=embedded`), the BOM is embedded inside the archive alongside the other assembly content. If the assembly uses `<includeBaseDirectory>true</includeBaseDirectory>`, the BOM is placed inside the base directory.

Setting `outputMode` to `external` writes the BOM as a separate file next to the archive, named after the archive with a `.cdx.json` (or `.cdx.xml`) suffix. When the BOM is external, the main component is updated with the SHA-256 hash of the archive after it is written. This is useful for CI pipelines that consume the BOM separately.

Setting `outputMode` to `all` produces both an embedded and an external BOM.

#### Attaching the SBOM as a Maven Artifact

Setting `attach` to `true` registers the external BOM as an attached Maven project artifact. This means the SBOM is installed to the local repository and deployed to remote repositories alongside the distribution archive. The attached artifact uses the same classifier as the distribution archive and an artifact type that encodes both the archive format and the SBOM format (e.g. `zip.cdx.json` or `tar.gz.cdx.json`, or `.cdx.xml` when using XML format). For example, for a distribution attached as `myapp-1.0-dist.zip`, the SBOM is installed as `myapp-1.0-dist.zip.cdx.json`. For multi-format assemblies (e.g. `zip` and `tar.gz`), each format generates and attaches its own SBOM with distinct coordinates, preventing Maven artifact collisions.

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <outputMode>external</outputMode>
        <attach>true</attach>
    </configuration>
</containerDescriptorHandler>
```

## Maven Plugin

The `assembly-sbom-maven-plugin` provides two goals for projects that need SBOM generation outside the assembly plugin workflow.

### `generate` Goal

Scans an exploded directory (e.g., an exploded WAR produced by `maven-war-plugin`) and generates a CycloneDX SBOM by identifying Maven artifacts via content-hash matching. Uses the same identification engine as the [assembly handler](#assembly-handler).

```xml
<plugin>
    <groupId>dev.cyberstamp.maven.assembly.sbom</groupId>
    <artifactId>assembly-sbom-maven-plugin</artifactId>
    <version>0.1.10</version>
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
| `identityEvidence` | `true` | Emit identity evidence for components this tool identifies (see [Evidence](#evidence)) |
| `librariesOnly` | `false` | Exclude generic file components from the output |
| `attach` | `false` | Attach the generated SBOM to the Maven project as an artifact with type `cdx.json` or `cdx.xml` and classifier `cyclonedx` |
| `schemaVersion` | _(latest)_ | CycloneDX schema version to use for SBOM output and serial-number computation, e.g. `1.5` or `1.6`. Defaults to the latest version supported by the integrated CycloneDX Java library |
| `product` | _(none)_ | User-configurable metadata for the main BOM component (CPE, description, supplier, manufacturer, publisher, copyright). See [Product](#product) |
| `mavenArtifactMatchers` | _(none)_ | Ordered list of matchers (`<central/>`, `<nexus>`, `<artifactory>`) that identify non-Maven-built jars (Gradle, Ant, ...) by their SHA-1. See [Maven Artifact Matchers](#maven-artifact-matchers) |

### `merge` Goal

Combines multiple CycloneDX SBOMs into a single BOM. This is useful when a project bundles components from multiple ecosystems (e.g., Maven + npm) and you need a unified SBOM.

```xml
<plugin>
    <groupId>dev.cyberstamp.maven.assembly.sbom</groupId>
    <artifactId>assembly-sbom-maven-plugin</artifactId>
    <version>0.1.10</version>
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
| `attach` | `false` | Attach the merged SBOM to the Maven project as an artifact with type `cdx.json` or `cdx.xml` and classifier `cyclonedx` |
| `schemaVersion` | _(latest)_ | CycloneDX schema version to use for the merged SBOM output, e.g. `1.5` or `1.6`. Defaults to the latest version supported by the integrated CycloneDX Java library |

By default, external SBOM components are added as top-level components alongside the base BOM's components (flat merge). This is appropriate when the external components are peers of the base components (e.g., npm dependencies alongside Maven dependencies in a WAR). Set `nested` to `true` to nest them as sub-components of the parent component instead, which is appropriate when the external SBOM describes contents _inside_ a specific artifact. Dependency entries from external SBOMs are always imported into the merged BOM's dependency section.

## How It Works

Both the assembly handler and the `generate` goal use the same core engine. This section describes the identification and merging features that apply to both.

### Artifact Identification

Every file in the assembly is inspected and classified as either a **library** (Maven artifact) or a **file** (non-artifact):

- **Content hash matching** — each archive entry's content hash is computed and looked up against a pre-built index of the project's resolved Maven artifacts. This identifies artifacts reliably regardless of filename (e.g., custom `outputFileNameMapping` in the assembly descriptor).
- **Deduplication** — if the same artifact appears at multiple locations in the archive, it is represented as a single component with multiple `evidence/occurrence` entries.
- **Remote Maven coordinates lookup** _(optional)_ — files that no other technique can identify (typically jars built with Gradle, Ant, or another non-Maven tool) can optionally have their Maven coordinates resolved by querying Maven Central, Nexus, or Artifactory with their SHA-1 content hash, turning them into proper `library` components instead of generic `file` components. Off unless matchers are configured; see [Maven Artifact Matchers](#maven-artifact-matchers).

Library components include full [Package URL](https://github.com/package-url/purl-spec) (PURL) identifiers. The default `jar` type is omitted (per the purl spec, `type` is a known but optional Maven qualifier), and any qualifiers are emitted in canonical alphabetical order:

```
pkg:maven/org.apache.commons/commons-io@2.22.0
pkg:maven/org.example/native-lib@1.0?classifier=linux-x86_64&type=so
```

### License Resolution

The generator resolves licenses for every Maven artifact component by reading the artifact's effective POM (including licenses inherited from parent POMs). License names and URLs are mapped to [SPDX](https://spdx.org/licenses/) license identifiers using the CycloneDX license database, which includes exact matches, name matching, URL matching, and fuzzy matching against common license name variants.

When no SPDX match is found, the raw license name and URL from the POM are preserved in the component. If an artifact's effective POM declares no licenses at all, a warning is logged. Set `failOnMissingLicense` to `true` to fail the build instead.

### Unpacked Archive Detection

When an assembly descriptor unpacks an artifact (e.g., a WAR with `<unpack>true</unpack>`), the handler detects the unpacked content by comparing SHA-256 hashes of the artifact's internal entries against the archive entries.

- The unpacked artifact is added as a single **library** component.
- Individual files from the unpacked archive that can be identified are **not** listed as separate file components — they appear as nested **library** components.
- Files that cannot be identified remain as **file** components.
- Nested JARs within the unpacked archive (e.g., JARs in a WAR's `WEB-INF/lib/`) are identified as separate **library** components with proper Maven PURLs.

Nested JAR identification uses three strategies:

1. **Reactor module lookup** — if the unpacked artifact is a module in the current reactor build, its resolved Maven dependencies are used to identify nested JARs by content hash.
2. **Effective POM resolution** — for non-reactor artifacts, the handler builds the artifact's effective POM model and resolves its compile/runtime-scoped dependencies from the Maven repository, then matches nested JARs by content hash.
3. **`pom.properties` parsing** — as a fallback, the handler reads `META-INF/maven/**/pom.properties` from inside each nested JAR to extract Maven coordinates.

### Shaded / Fat JAR Detection

Shaded (fat) JARs bundle their dependencies inside a single JAR file. These JARs contain multiple `META-INF/maven/**/pom.properties` entries — one for the main artifact and one for each bundled dependency.

When a nested JAR contains multiple `pom.properties` entries, the handler attempts to identify the owner by matching the JAR filename against the `artifactId` values. For example, a file named `nimbus-jose-jwt-10.6.jar` containing `pom.properties` for `nimbus-jose-jwt`, `jcip-annotations`, and `gson` would be identified as `nimbus-jose-jwt` because only that `artifactId` appears in the filename. The bundled dependencies (`jcip-annotations` and `gson`) are then registered as nested **library** components under the identified artifact.

When the filename is ambiguous (zero or multiple `artifactId` values match), the JAR appears as a **file** component with the discovered Maven artifacts nested as **library** sub-components. This preserves all available identity information without making an incorrect attribution.

### Dependency Graph

The BOM includes a CycloneDX dependency graph reflecting the Maven dependency tree. Only artifacts that are actually present in the assembly are included.

- **Direct vs. transitive** — the graph preserves the Maven dependency hierarchy. Transitive dependencies are connected through their parent, not listed as direct dependencies of the main component.
- **Unpacked artifact dependencies** — nested JARs identified within unpacked archives are connected to their parent artifact via dependency edges.
- **Unknown dependencies** — a component whose dependencies were never resolved has no dependency entry, since an empty entry would declare that it has none. This applies to artifacts bundled in a shaded JAR and to JARs identified from their `pom.properties`, a detected SBOM or a remote lookup rather than as project dependencies.
- **Several copies of an artifact** — when the same artifact ships more than once (e.g. at the top level and inside a WAR, or bundled in a shaded JAR), each copy is a separate component. One keeps the plain bom-ref (the first met, top-level first, or, when the artifact has a dependency entry, the first whose dependencies are known); the others get `#2`, `#3`, ... appended. A copy whose dependencies are known gets the artifact's dependency entry, and a component depending on the artifact also depends on the copies nested in it. The main component depends on what ships at the top level, so its dependency follows the top-level copy, whichever bom-ref it ends up with.

### SBOM Merging

Distribution archives often bundle artifacts from non-Maven ecosystems — most commonly JavaScript libraries inside WARs or JARs. The generator can detect and integrate CycloneDX SBOMs from those ecosystems, turning otherwise unidentified files into properly typed LIBRARY components with Package URLs, licenses, and dependency relationships.

#### Auto-detection

CycloneDX SBOM files (`.cdx.json` or `.cdx.xml`) are automatically detected in two places:

1. **Archive entries** — when an artifact is unpacked into the distribution (e.g., a WAR with `<unpack>true</unpack>`), any SBOM file among the unpacked content is detected. The parent is determined by the directory structure.
2. **Inside bundled JARs/WARs** — matched artifacts that are ZIP-based archives are scanned for embedded SBOM files.

When both JSON and XML variants of the same SBOM exist (same filename stem in the same directory), the JSON variant is preferred and the XML duplicate is skipped.

#### Identification from Detected SBOMs

SBOMs inside resolved artifacts also serve as a source of hash-to-purl mappings. Maven project dependencies and reactor modules remain the primary source; for a jar they cannot account for — at the top level of the archive or nested inside an unpacked artifact — the generator looks up its content hash among the `pkg:maven` components of those SBOMs **before** reading the jar's `pom.properties`. A matched jar takes the purl identity's technique and confidence from the SBOM that listed it (none if that SBOM recorded no purl identity).

The claim is cross-checked against the jar's own `pom.properties` (groupId, artifactId and version):

| Jar's `pom.properties` | Result |
|---|---|
| none | SBOM identity used as is |
| one of them matches the SBOM | SBOM identity used as is; the other descriptors are nested as bundled dependencies |
| same groupId and artifactId, different version | SBOM claim rejected; the jar is identified from its `pom.properties` |
| none for the SBOM's groupId and artifactId | SBOM purl used; the descriptors are nested as bundled dependencies. Confidence is kept when the SBOM identified the jar by `hash-comparison` (its build matched these exact bytes), otherwise capped at 0.5 |

When several SBOMs list the same hash, agreeing claims keep the highest confidence; claims naming different purls are all discarded (with a warning) and the jar falls through to `pom.properties`. Setting `embeddedSboms` to `ignore` disables this lookup too.

#### Handling Modes

The `embeddedSboms` option controls what happens with detected SBOMs:

- **`merge`** (default) — the SBOM's components are imported as nested sub-components of the containing artifact. Dependency entries are imported into the distribution BOM's dependency section. No cross-ecosystem dependency edges are created — nesting already captures the containment relationship.
- **`link`** — an `externalReference` of type `bom` is added to the containing artifact, pointing to the SBOM file's location within the archive. The SBOM file remains in the archive.
- **`ignore`** — embedded SBOMs are not processed.

#### External SBOMs

The `externalSboms` option accepts a comma-separated list of file paths to CycloneDX SBOMs generated outside the Maven build (e.g., by `cdxgen`, `@cyclonedx/cyclonedx-npm`, or pnpm). These SBOMs are:

1. **Used for archive entry matching** — component hashes from external SBOMs are checked against unmatched archive entries, before their `pom.properties` and before [detected SBOMs](#identification-from-detected-sboms). If a match is found, the entry is identified from the external SBOM rather than appearing as an unidentified FILE component. A `pkg:maven` claim is first cross-checked against the jar's own `pom.properties`: when a descriptor declares the same groupId and artifactId with another version, the claim is not used and its component is not merged; the jar goes on to the next identification steps ([detected SBOMs](#identification-from-detected-sboms), then its `pom.properties`). For an accepted claim, the jar's other descriptors that the external component does not already list are added under it as bundled dependencies.
2. **Merged flat as top-level components** — external SBOM components are added as peers of the distribution's own components (not nested under the main component). Their dependency entries are imported into the BOM's dependency section, and the external SBOM's top-level dependencies are linked under the distribution's main component. A component from an external SBOM keeps the identity evidence its SBOM carried. If that evidence has no purl identity and the jar's own `pom.properties` declare exactly its coordinates, this tool records that as `manifest-analysis` at confidence 1.0; the same applies to its nested entries (such as dependencies bundled in a shaded jar) whose coordinates one of the jar's `pom.properties` declares exactly. Otherwise it adds none (see [Evidence](#evidence)).

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

#### Generating JavaScript SBOMs

| Package Manager | Tool |
|---|---|
| npm | [`@cyclonedx/cyclonedx-npm`](https://www.npmjs.com/package/@cyclonedx/cyclonedx-npm) |
| Yarn | [`@cyclonedx/cyclonedx-node-yarn`](https://github.com/CycloneDX/cyclonedx-node-yarn) |
| pnpm | [`cdxgen`](https://www.npmjs.com/package/@cyclonedx/cdxgen) |
| Any | [`cdxgen`](https://www.npmjs.com/package/@cyclonedx/cdxgen) (multi-ecosystem) |

### Cryptography Bills of Materials (CBOM)

A [CBOM](https://cyclonedx.org/capabilities/cbom/) is the CycloneDX cryptography extension (schema 1.6+): it inventories cryptographic assets — algorithms, protocols, certificates, and key material — discovered in an application, so they can be assessed for issues like post-quantum readiness.

This project **does not generate** CBOM data. Doing so requires static analysis of source or bytecode to find cryptographic API usage, which is a different discipline from the content-hash identification this project performs. Instead, it **consumes** CBOMs through the same merge machinery used for other ecosystems: generate a CBOM with a dedicated tool, then merge it into the distribution SBOM via [`externalSboms`](#external-sboms) (or let it be auto-detected as an [embedded SBOM](#auto-detection)).

#### Generating a CBOM for a Java application

| Tool | How it runs | Java coverage |
|---|---|---|
| [IBM Sonar Cryptography](https://github.com/cbomkit/sonar-cryptography) | SonarQube plugin — analyzes a **built** project | Highest: JCA/JCE and BouncyCastle lightweight API |
| [CBOMkit Action](https://github.com/cbomkit/cbomkit-action) | GitHub Action — builds, then scans, in CI | High |
| [CBOMkit](https://github.com/cbomkit/cbomkit) | Docker/Podman/Helm toolset — scans a git repo or PURL, plus a viewer, REST API, and compliance checks | Moderate (scans source **without building**, so some symbols go unresolved) |
| [`cdxgen --include-crypto`](https://github.com/CycloneDX/cdxgen) | Single CLI, no server (`cdxgen -t java --include-crypto -o crypto.cdx.json .`) | Moderate |

All of these emit CycloneDX CBOM JSON. Scanners that run **after a build** (the SonarQube plugin, the Action) produce the most accurate Java results, because resolved symbols are what make cryptographic-API detection reliable.

#### Merging a CBOM into the distribution SBOM

```xml
<containerDescriptorHandler>
    <handlerName>sbom</handlerName>
    <configuration>
        <outputMode>external</outputMode>
        <externalSboms>target/crypto.cdx.json</externalSboms>
    </configuration>
</containerDescriptorHandler>
```

The merge preserves `cryptographic-asset` components and their full `cryptoProperties` (algorithm, certificate, protocol, and related-material details), along with `dependsOn` relationships between them. This round trip is covered by `CbomMergeRoundTripTest`.

**Limitations:**

- The CBOM-specific `provides` dependency relationship is not preserved — the integrated CycloneDX Java library models only `dependsOn`, so `provides` edges are dropped at parse time. Ordinary `dependsOn` edges round-trip normally.
- `cryptoProperties` require CycloneDX schema 1.6 or later. The default `schemaVersion` tracks the latest version supported by the integrated library (1.6+), so no configuration is needed; explicitly setting `schemaVersion` to 1.5 or lower will silently drop crypto data on output.

### Reproducible Builds

The generator produces deterministic output for reproducible builds:

- **Serial number** — a UUID derived from the serialized BOM content (compact JSON), making it a pure function of what the SBOM describes. Two builds with identical content produce the same serial number; any change to components, dependencies, properties, or metadata produces a different one.
- **Timestamp** — uses `project.build.outputTimestamp` when set (the standard Maven [reproducible builds](https://maven.apache.org/guides/mini/guide-reproducible-builds.html) property), otherwise falls back to the current time. Since the timestamp is part of the serialized content, setting `project.build.outputTimestamp` is required for fully reproducible serial numbers.
- **Ordering** — components and dependencies are sorted alphabetically, so identical inputs produce identical output regardless of filesystem or iteration order.

### CycloneDX Component Types

| Component Type | When Used |
|---|---|
| `application` | The main assembly (appears in BOM metadata) |
| `library` | Maven artifacts — both packed JARs and unpacked archives. May appear as nested sub-components of other `library` or `file` components (e.g., bundled dependencies inside a shaded JAR) |
| `file` | Non-artifact files (config files, scripts, schemas, licenses, etc.) and JARs that could not be positively identified as Maven artifacts. May contain nested `library` sub-components when Maven artifacts are discovered inside (e.g., via `pom.properties` in a shaded JAR) |

The main `application` component's PURL includes the archive type derived from the output filename (e.g., `zip`, `tar.gz`) and a classifier. The classifier is determined from the assembly plugin configuration: if an explicit `<classifier>` is set it is used, otherwise the assembly descriptor id is used unless `<appendAssemblyId>` is `false`, in which case the classifier is omitted.

### Evidence

Each component includes CycloneDX `evidence` with `occurrence` entries recording where it appears in the archive.

Components this tool identifies also carry a purl `identity` recording how they were identified: a single method with the technique that actually identified the component and a confidence reflecting how strong that evidence is. No `value` is emitted.

| Situation | Technique | Confidence |
|---|---|---|
| Archive entry's hash matched a resolved Maven artifact | `hash-comparison` | 1.0 |
| Coordinates read from the jar's own `pom.properties`, owner unambiguous | `manifest-analysis` | 1.0 |
| Unpacked artifact, matched on its member files | `hash-comparison` | 0.8 |
| Shaded jar whose owner was chosen by matching its filename against the embedded `artifactId`s | `manifest-analysis` | 0.5 |
| Bundled dependency, coordinates from its own `pom.properties` | `manifest-analysis` | 1.0 |
| Shaded jar with no resolvable owner: each embedded artifact, nested under the file | `manifest-analysis` | 1.0 |
| Non-Maven-built jar, matched via [remote Maven coordinates lookup](#maven-artifact-matchers) | `hash-comparison` | 0.9 |
| Jar whose hash is listed in an SBOM found inside a resolved artifact ([details](#identification-from-detected-sboms)) | from that SBOM | from that SBOM; at most 0.5 if the jar's `pom.properties` are all for other artifacts and the SBOM's technique is not `hash-comparison`; none if the SBOM has no purl identity |

Components that were not identified by this tool get no identity of its making:

- Components from external or embedded SBOMs carry the identity evidence their SBOM provided, or none. Where such a component merges with one this tool already identified, this tool's identity is kept. An external `pkg:maven` component without a purl identity whose coordinates the matched jar's own `pom.properties` confirm gets `manifest-analysis` 1.0 from this tool; so does each of its nested entries whose coordinates one of the jar's `pom.properties` declares exactly.
- Components built directly through the `assembly-sbom-core` model API carry identity evidence only if the producer supplies an `Identification`.
- Non-Maven components (`file`, generic, npm) carry occurrences only.

Set `identityEvidence` to `false` to emit no identity evidence of this tool's own; identity from external or embedded SBOMs is still preserved.

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

## Contributing

Contributions are welcome! Please see the [Contributing Guide](CONTRIBUTING.md) for build instructions, code formatting guidelines, and tips for submitting pull requests.

