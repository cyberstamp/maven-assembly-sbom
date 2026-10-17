package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.List;

import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Byte-identity regression guard for {@link BomRenderer}.
 *
 * <p>
 * The purpose of this test is to guarantee that SBOM output stays
 * byte-for-byte stable. The other tests assert that structurally (component
 * fields, nesting, dependency edges); this one pins the actual serialized
 * bytes: it builds a fixed {@link AssemblyComponents} model exercising the
 * tricky paths (occurrence merge on a duplicate PURL, a nested/shaded
 * component, a plain FILE component, an inter-artifact dependency edge, and
 * all three license shapes), renders it, serializes it and compares against
 * a checked-in golden document.
 * </p>
 *
 * <p>
 * Because the input model is fixed and the timestamp/schema version are pinned,
 * the output — including the content-derived {@code serialNumber} — is fully
 * deterministic. If a change to the rendering or serialization path alters the
 * output, this test fails with a full diff. When the change is intentional,
 * regenerate the golden with:
 * </p>
 *
 * <pre>{@code mvn -pl core test -Dtest=GoldenBomTest -Dgolden.regenerate=true}</pre>
 *
 * <p>
 * then review the resulting diff in
 * {@code core/src/test/resources/golden/assembly-golden.cdx.json} before
 * committing.
 * </p>
 */
class GoldenBomTest {

    private static final String GOLDEN_RESOURCE = "/golden/assembly-golden.cdx.json";
    private static final Path GOLDEN_SOURCE_PATH = Path.of("src/test/resources/golden/assembly-golden.cdx.json");

    /** Pinned so the golden bytes never drift with the CycloneDX library default. */
    private static final String SCHEMA_VERSION = "1.6";

    @TempDir
    Path tempDir;

    @Test
    void renderedBomMatchesGolden() throws Exception {
        Bom bom = new BomRenderer().render(buildFixedModel());
        Version schemaVersion = SchemaVersions.resolve(SCHEMA_VERSION);
        Path out = tempDir.resolve("golden.cdx.json");
        BomWriter.writeJson(bom, out, true, schemaVersion);
        String actual = Files.readString(out);

        if (Boolean.getBoolean("golden.regenerate")) {
            Files.createDirectories(GOLDEN_SOURCE_PATH.getParent());
            Files.writeString(GOLDEN_SOURCE_PATH, actual, StandardCharsets.UTF_8);
            System.out.println("Regenerated golden: " + GOLDEN_SOURCE_PATH.toAbsolutePath());
            return;
        }

        String expected = readGolden();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode expectedJson = mapper.readTree(expected);
        JsonNode actualJson = mapper.readTree(actual);

        boolean identical = expectedJson.equals(actualJson);

        assertTrue(identical,
                "Rendered BOM diverged from the golden document. If this change is "
                        + "intentional, regenerate with -Dgolden.regenerate=true and review the diff.");
    }

    private String readGolden() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(GOLDEN_RESOURCE)) {
            assertNotNull(in, "Golden resource " + GOLDEN_RESOURCE + " is missing; "
                    + "generate it with -Dgolden.regenerate=true");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Builds a fixed model exercising the byte-identity-critical paths. Every
     * value is a literal so the serialized output is fully deterministic.
     */
    private AssemblyComponents buildFixedModel() {
        AssemblyComponents model = new AssemblyComponents();

        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("demo-dist");
        metadata.setProjectVersion("1.0.0");
        metadata.setAssemblyId("dist");
        // Fixed instant so the metadata timestamp never varies.
        metadata.setTimestamp(new Date(1_700_000_000_000L));
        metadata.setHashAlgorithmSpec("SHA-256");
        metadata.setClassifier("dist");
        metadata.setArchiveType("zip");
        metadata.setProjectLicenses(List.of(
                LicenseInfo.spdx("Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0")));
        metadata.setToolGroupId("dev.cyberstamp.maven.assembly.sbom");
        metadata.setToolArtifactId("assembly-sbom-core");
        metadata.setToolVersion("0.0.0-golden");
        metadata.setToolLicenses(List.of(LicenseInfo.spdx("Apache-2.0", null)));
        metadata.setToolHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        model.setMetadata(metadata);

        ArtifactCoords alpha = ArtifactCoords.of("org.example", "alpha", "1.0");
        ArtifactCoords beta = ArtifactCoords.of("org.example", "beta", "2.0");

        // A shaded/bundled dependency nested under alpha.
        PackageComponent bundled = new PackageComponent(
                ArtifactCoords.of("com.bundled", "shaded-dep", "3.1"),
                "lib/alpha.jar", null, List.of(), List.of());

        // Top-level alpha with a nested component and an SPDX-id license.
        model.addComponent(new PackageComponent(alpha, "lib/alpha.jar",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                List.of(LicenseInfo.spdx("Apache-2.0",
                        "https://www.apache.org/licenses/LICENSE-2.0")),
                List.of(bundled)));

        // Same PURL again at a second path with no license -> occurrence merge,
        // first-wins licenses.
        model.addComponent(new PackageComponent(alpha, "other/alpha.jar",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                List.of(), List.of()));

        // Top-level beta with an SPDX-expression license.
        model.addComponent(new PackageComponent(beta, "lib/beta.jar",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                List.of(LicenseInfo.expression("(MIT OR Apache-2.0)")), List.of()));

        // A plain FILE component (raw license comes from project licenses).
        model.addComponent(new FileComponent("bin/launcher.sh",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                List.of()));

        // An explicit inter-artifact dependency: alpha depends on beta.
        model.addDependencyEdge(new DependencyEdge(alpha, beta, true));

        return model;
    }
}
