package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link BomRenderer}: rendering {@link AssemblyComponents} to
 * CycloneDX {@link Bom}.
 */
class BomRendererTest {

    /**
     * (a) One Maven top-level component with hash + one archivePath →
     * correct purl/bom-ref/hash/evidence(Occurrence+Identity)/license.
     */
    @Test
    void testSingleMavenComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setTimestamp(new Date(1234567890000L));
        model.setMetadata(metadata);

        ArtifactCoords coords = ArtifactCoords.of("com.example", "lib", "2.0.0");
        PackageComponent pkg = new PackageComponent(
                coords,
                "lib/lib-2.0.0.jar",
                "abc123",
                List.of(LicenseInfo.spdx("Apache-2.0")),
                List.of(), true, Identification.hashMatch());
        model.addComponent(pkg);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertNotNull(bom);
        assertNotNull(bom.getMetadata());
        assertNotNull(bom.getComponents());
        assertEquals(1, bom.getComponents().size());

        Component comp = bom.getComponents().get(0);
        assertEquals("com.example", comp.getGroup());
        assertEquals("lib", comp.getName());
        assertEquals("2.0.0", comp.getVersion());
        assertEquals(Component.Type.LIBRARY, comp.getType());

        String expectedPurl = "pkg:maven/com.example/lib@2.0.0";
        assertEquals(expectedPurl, comp.getPurl());
        assertEquals(expectedPurl, comp.getBomRef());

        assertNotNull(comp.getHashes());
        assertEquals(1, comp.getHashes().size());
        Hash hash = comp.getHashes().get(0);
        assertEquals("SHA-256", hash.getAlgorithm());
        assertEquals("abc123", hash.getValue());

        Evidence evidence = comp.getEvidence();
        assertNotNull(evidence);
        assertNotNull(evidence.getOccurrences());
        assertEquals(1, evidence.getOccurrences().size());
        assertEquals("lib/lib-2.0.0.jar", evidence.getOccurrences().get(0).getLocation());

        assertNotNull(evidence.getIdentities());
        assertEquals(1, evidence.getIdentities().size());
        assertEquals(Identity.Field.PURL,
                evidence.getIdentities().get(0).getField());
        assertEquals(1.0, evidence.getIdentities().get(0).getConfidence());
        Method method = evidence.getIdentities().get(0).getMethods().get(0);
        assertEquals(Method.Technique.HASH_COMPARISON,
                method.getTechnique());
        assertEquals(1.0, method.getConfidence());
        assertNull(method.getValue(), "this tool never emits methods[].value");

        assertNotNull(comp.getLicenses());
        assertNotNull(comp.getLicenses().getLicenses());
        assertEquals(1, comp.getLicenses().getLicenses().size());
        License license = comp.getLicenses().getLicenses().get(0);
        assertEquals("Apache-2.0", license.getId());
    }

    /**
     * (b) Same coords added twice at two paths → single component with two
     * Occurrences, licenses from the first.
     */
    @Test
    void testOccurrenceMerge() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords coords = ArtifactCoords.of("com.example", "lib", "2.0.0");
        // First occurrence with license and hash
        PackageComponent pkg1 = new PackageComponent(
                coords,
                "lib/lib-2.0.0.jar",
                "abc123",
                List.of(LicenseInfo.spdx("Apache-2.0")),
                List.of());
        model.addComponent(pkg1);

        // Second occurrence at different path, different license (should be ignored)
        PackageComponent pkg2 = new PackageComponent(
                coords,
                "other/lib-2.0.0.jar",
                "abc123",
                List.of(LicenseInfo.spdx("MIT")),
                List.of());
        model.addComponent(pkg2);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        // Should result in a single component
        assertEquals(1, bom.getComponents().size());

        Component comp = bom.getComponents().get(0);
        assertEquals("com.example", comp.getGroup());
        assertEquals("lib", comp.getName());
        assertEquals("2.0.0", comp.getVersion());

        // Should have two occurrences
        Evidence evidence = comp.getEvidence();
        assertNotNull(evidence);
        assertNotNull(evidence.getOccurrences());
        assertEquals(2, evidence.getOccurrences().size());
        assertEquals("lib/lib-2.0.0.jar", evidence.getOccurrences().get(0).getLocation());
        assertEquals("other/lib-2.0.0.jar", evidence.getOccurrences().get(1).getLocation());

        // License should be from the first occurrence
        assertNotNull(comp.getLicenses());
        assertNotNull(comp.getLicenses().getLicenses());
        assertEquals(1, comp.getLicenses().getLicenses().size());
        assertEquals("Apache-2.0", comp.getLicenses().getLicenses().get(0).getId());
    }

    /**
     * (c) A nested Maven artifact under a parent → nested + sorted.
     */
    @Test
    void testNestedComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords nestedCoords = ArtifactCoords.of("com.nested", "dep", "1.0");
        PackageComponent nested = new PackageComponent(
                nestedCoords,
                "lib/parent.war/WEB-INF/lib/dep-1.0.jar",
                "def456",
                List.of(LicenseInfo.spdx("MIT")),
                List.of());

        ArtifactCoords parentCoords = ArtifactCoords.of("com.example", "parent", "2.0.0");
        PackageComponent parent = new PackageComponent(
                parentCoords,
                "lib/parent.war",
                "abc123",
                List.of(LicenseInfo.spdx("Apache-2.0")),
                List.of(nested));
        model.addComponent(parent);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertEquals(1, bom.getComponents().size());
        Component parentComp = bom.getComponents().get(0);
        assertEquals("com.example", parentComp.getGroup());
        assertEquals("parent", parentComp.getName());

        assertNotNull(parentComp.getComponents());
        assertEquals(1, parentComp.getComponents().size());
        Component nestedComp = parentComp.getComponents().get(0);
        assertEquals("com.nested", nestedComp.getGroup());
        assertEquals("dep", nestedComp.getName());
        assertEquals("1.0", nestedComp.getVersion());
        assertEquals("pkg:maven/com.nested/dep@1.0", nestedComp.getPurl());
    }

    /**
     * (d) A FileComponent → file: bom-ref + generic purl + project license.
     */
    @Test
    void testFileComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setProjectLicenses(List.of(LicenseInfo.spdx("Apache-2.0")));
        model.setMetadata(metadata);

        FileComponent file = new FileComponent(
                "bin/script.sh",
                "xyz789",
                List.of());
        model.addComponent(file);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertEquals(1, bom.getComponents().size());
        Component comp = bom.getComponents().get(0);
        assertEquals(Component.Type.FILE, comp.getType());
        assertEquals("script.sh", comp.getName());
        assertEquals("file:bin/script.sh", comp.getBomRef());

        String purl = comp.getPurl();
        assertTrue(purl.startsWith("pkg:generic/script.sh"));
        assertTrue(purl.contains("checksum=sha256:xyz789"));

        // File should have project licenses
        assertNotNull(comp.getLicenses());
        assertNotNull(comp.getLicenses().getLicenses());
        assertEquals(1, comp.getLicenses().getLicenses().size());
        assertEquals("Apache-2.0", comp.getLicenses().getLicenses().get(0).getId());
    }

    /**
     * A generic (non-Maven) package component — e.g. a Galleon-assembled shaded
     * JAR — must render with its name and version, a {@code pkg:generic} purl,
     * and its nested dependencies.
     */
    @Test
    void testGenericPackageComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        PackageComponent nested = PackageComponent.of(
                ArtifactCoords.of("org.jboss", "dep-a", "1.0"), null, null);
        PackageComponent shaded = new PackageComponent(
                new GenericPackageRef("jboss-cli-client", "31.0.0.Final"),
                "bin/client/jboss-cli-client.jar", null,
                List.of(), List.of(nested));
        model.addComponent(shaded);

        Bom bom = new BomRenderer().render(model);

        Component comp = bom.getComponents().stream()
                .filter(c -> "jboss-cli-client".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(comp);
        assertEquals(Component.Type.LIBRARY, comp.getType());
        assertEquals("31.0.0.Final", comp.getVersion());
        assertEquals("pkg:generic/jboss-cli-client@31.0.0.Final", comp.getPurl());
        assertEquals("pkg:generic/jboss-cli-client@31.0.0.Final", comp.getBomRef());
        assertNotNull(comp.getComponents());
        assertEquals(1, comp.getComponents().size());
        assertEquals("dep-a", comp.getComponents().get(0).getName());
    }

    /**
     * When {@code mainComponentPurl} is set, the main component uses it verbatim
     * for both {@code purl} and {@code bom-ref} (rather than a derived Maven
     * purl), and the dependency-graph root references that same bom-ref. This
     * lets non-Maven producers (e.g. a provisioned distribution) give the main
     * component a synthetic identity.
     */
    @Test
    void testMainComponentSyntheticPurlOverride() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectArtifactId("JBoss EAP");
        metadata.setProjectVersion("8.1 Update 7.1");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setMainComponentPurl("pkg:generic/jboss-eap@8.1-update-7.1");
        model.setMetadata(metadata);
        model.addComponent(PackageComponent.of(
                ArtifactCoords.of("org.example", "lib", "1.0"), "lib/lib-1.0.jar", "h"));

        Bom bom = new BomRenderer().render(model);

        Component main = bom.getMetadata().getComponent();
        assertEquals("JBoss EAP", main.getName());
        assertEquals("8.1 Update 7.1", main.getVersion());
        assertEquals("pkg:generic/jboss-eap@8.1-update-7.1", main.getPurl());
        assertEquals("pkg:generic/jboss-eap@8.1-update-7.1", main.getBomRef());
        assertTrue(bom.getDependencies().stream()
                .anyMatch(d -> "pkg:generic/jboss-eap@8.1-update-7.1".equals(d.getRef())),
                "dependency-graph root must reference the synthetic bom-ref");
    }

    /**
     * (e) A small dependency graph → sorted dependency tree + main dep filtering.
     */
    @Test
    void testDependencyGraph() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords lib1 = ArtifactCoords.of("com.example", "lib1", "1.0");
        ArtifactCoords lib2 = ArtifactCoords.of("com.example", "lib2", "2.0");

        PackageComponent lib1Copy = PackageComponent.of(lib1, "lib/lib1-1.0.jar", "hash1");
        PackageComponent lib2Copy = PackageComponent.of(lib2, "lib/lib2-2.0.jar", "hash2");
        model.addComponent(lib1Copy);
        model.addComponent(lib2Copy);

        // lib1 depends on lib2
        model.addDependencyEdge(new DependencyEdge(lib1Copy.id(), lib2Copy.id()));

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertNotNull(bom.getDependencies());
        assertTrue(bom.getDependencies().size() >= 3); // main, lib1, lib2

        // Find main dependency
        String mainPurl = "pkg:maven/org.example/my-app@1.0.0";
        Dependency mainDep = bom.getDependencies().stream()
                .filter(d -> mainPurl.equals(d.getRef()))
                .findFirst()
                .orElse(null);
        assertNotNull(mainDep);

        // Main should only have lib1 as direct child (lib2 is transitive through lib1)
        assertEquals(1, mainDep.getDependencies().size());
        assertEquals("pkg:maven/com.example/lib1@1.0", mainDep.getDependencies().get(0).getRef());

        // lib1 should have lib2 as a dependency
        Dependency lib1Dep = bom.getDependencies().stream()
                .filter(d -> "pkg:maven/com.example/lib1@1.0".equals(d.getRef()))
                .findFirst()
                .orElse(null);
        assertNotNull(lib1Dep);
        assertEquals(1, lib1Dep.getDependencies().size());
        assertEquals("pkg:maven/com.example/lib2@2.0", lib1Dep.getDependencies().get(0).getRef());
    }

    /**
     * A component created with {@code dependenciesKnown = false} is not declared
     * as an empty leaf entry in the dependency graph, while one with known
     * dependencies (the default) is. This lets a producer mark exactly those
     * components whose dependencies it never resolved, so "unknown" is not
     * misreported as "no dependencies".
     */
    @Test
    void testComponentWithUnknownDependenciesOmittedFromGraph() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");
        model.setMetadata(metadata);

        // lib1: dependencies known (default) → declared as a leaf entry.
        model.addComponent(PackageComponent.of(
                ArtifactCoords.of("com.example", "lib1", "1.0"), "lib/lib1-1.0.jar", "hash1"));
        // lib2: dependencies unknown → omitted from the dependency graph.
        model.addComponent(PackageComponent.of(
                ArtifactCoords.of("com.example", "lib2", "2.0"), "lib/lib2-2.0.jar", "hash2", false));

        final String mainPurl = "pkg:maven/org.example/my-app@1.0.0";
        final String lib1Purl = "pkg:maven/com.example/lib1@1.0";
        final String lib2Purl = "pkg:maven/com.example/lib2@2.0";

        Bom bom = new BomRenderer().render(model);

        // Main references both (they are components), but only lib1 has a leaf entry.
        Dependency mainDep = bom.getDependencies().stream()
                .filter(d -> mainPurl.equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(mainDep);
        assertEquals(2, mainDep.getDependencies().size());
        assertTrue(bom.getDependencies().stream().anyMatch(d -> lib1Purl.equals(d.getRef())),
                "component with known dependencies should have a leaf entry");
        assertTrue(bom.getDependencies().stream().noneMatch(d -> lib2Purl.equals(d.getRef())),
                "component with unknown dependencies should not have a leaf entry");
    }

    @Test
    void renderDoesNotSetSerialNumber() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setTimestamp(new Date(1234567890000L));
        model.setMetadata(metadata);

        ArtifactCoords coords = ArtifactCoords.of("com.example", "lib", "2.0.0");
        model.addComponent(PackageComponent.of(coords, "lib/lib-2.0.0.jar", "abc123"));

        Bom bom = new BomRenderer().render(model);
        assertNull(bom.getSerialNumber());
    }

    /**
     * Tests nested-child filter: a PackageComponent with a nested JAR
     * AND a DependencyEdge(parent → jar) should render a parent Dependency with
     * ZERO children (the nested jar is filtered out per BomBuilder.mergeDependencyGraphs L707).
     */
    /**
     * Tests occurrence merge with dependencies: a component that appears at
     * two paths (occurrence merge) and is also a dependency parent should
     * still get its dependency entries.
     */
    @Test
    void testOccurrenceMergeWithDependencies() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords parent = ArtifactCoords.of("com.example", "parent", "1.0");
        ArtifactCoords child = ArtifactCoords.of("com.example", "child", "2.0");

        // Parent appears at two paths (should trigger occurrence merge)
        PackageComponent parentCopy = PackageComponent.of(parent, "lib/parent-1.0.jar", "hash1");
        model.addComponent(parentCopy);
        model.addComponent(PackageComponent.of(parent, "other/parent-1.0.jar", "hash1"));

        // Child appears once
        PackageComponent childCopy = PackageComponent.of(child, "lib/child-2.0.jar", "hash2");
        model.addComponent(childCopy);

        // parent depends on child
        model.addDependencyEdge(new DependencyEdge(parentCopy.id(), childCopy.id()));

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        // Should result in 2 components (parent merged, child separate)
        assertEquals(2, bom.getComponents().size());

        // Parent should have 2 occurrences
        Component parentComp = bom.getComponents().stream()
                .filter(c -> "parent".equals(c.getName()))
                .findFirst()
                .orElse(null);
        assertNotNull(parentComp);
        assertEquals(2, parentComp.getEvidence().getOccurrences().size());

        // Parent's dependency entry should still exist with child
        String parentPurl = "pkg:maven/com.example/parent@1.0";
        Dependency parentDep = bom.getDependencies().stream()
                .filter(d -> parentPurl.equals(d.getRef()))
                .findFirst()
                .orElse(null);
        assertNotNull(parentDep, "Parent should have a dependency entry");
        assertEquals(1, parentDep.getDependencies().size());
        assertEquals("pkg:maven/com.example/child@2.0", parentDep.getDependencies().get(0).getRef());
    }

    // ---- Identity evidence ----

    private static Bom renderPackages(BomRenderer renderer, PackageComponent... pkgs) {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");
        metadata.setTimestamp(new Date(1234567890000L));
        model.setMetadata(metadata);
        for (PackageComponent pkg : pkgs) {
            model.addComponent(pkg);
        }
        return renderer.render(model);
    }

    private static List<Identity> identities(Bom bom) {
        Evidence evidence = bom.getComponents().get(0).getEvidence();
        return evidence == null ? null : evidence.getIdentities();
    }

    @Test
    void componentWithoutIdentificationHasNoIdentity() {
        Bom bom = renderPackages(new BomRenderer(),
                PackageComponent.of(ArtifactCoords.of("com.example", "a", "1"), "lib/a.jar", "h"));
        Evidence evidence = bom.getComponents().get(0).getEvidence();
        assertEquals("lib/a.jar", evidence.getOccurrences().get(0).getLocation());
        assertTrue(evidence.getIdentities() == null || evidence.getIdentities().isEmpty());
    }

    @Test
    void genericComponentRendersProducerIdentification() {
        Bom bom = renderPackages(new BomRenderer(), new PackageComponent(
                new GenericPackageRef("shaded-thing", "1.0"), "lib/s.jar", null,
                List.of(), List.of(), false, new Identification(Technique.ATTESTATION, 0.9)));
        var identity = identities(bom).get(0);
        assertEquals(0.9, identity.getConfidence());
        assertEquals(Method.Technique.ATTESTATION,
                identity.getMethods().get(0).getTechnique());
        assertEquals(0.9, identity.getMethods().get(0).getConfidence());
    }

    @Test
    void everyTechniqueMapsToCycloneDx() {
        for (Technique technique : Technique.values()) {
            Bom bom = renderPackages(new BomRenderer(), PackageComponent.of(
                    ArtifactCoords.of("com.example", "a", "1"), "lib/a.jar", null, true,
                    new Identification(technique, 0.5)));
            assertEquals(technique.name(), identities(bom).get(0).getMethods().get(0).getTechnique().name());
        }
    }

    @Test
    void laterInstanceSuppliesIdentityWhenFirstHasNone() {
        ArtifactCoords coords = ArtifactCoords.of("com.example", "x", "1");
        Bom bom = renderPackages(new BomRenderer(),
                PackageComponent.of(coords, "a/x.jar", null),
                PackageComponent.of(coords, "b/x.jar", null, true, Identification.hashMatch()));
        assertEquals(1, bom.getComponents().size());
        assertEquals(2, bom.getComponents().get(0).getEvidence().getOccurrences().size());
        assertEquals(Method.Technique.HASH_COMPARISON,
                identities(bom).get(0).getMethods().get(0).getTechnique());
    }

    @Test
    void firstIdentificationWinsOverLater() {
        ArtifactCoords coords = ArtifactCoords.of("com.example", "x", "1");
        Bom bom = renderPackages(new BomRenderer(),
                PackageComponent.of(coords, "a/x.jar", null, true, Identification.pomPropertiesFilenameOwner()),
                PackageComponent.of(coords, "b/x.jar", null, true, Identification.hashMatch()));
        assertEquals(1, identities(bom).size());
        assertEquals(0.5, identities(bom).get(0).getConfidence());
    }

    /**
     * A shaded jar bundles X (no file of its own) and X's real jar also ships
     * at the top level. The top-level jar's path belongs to the top-level X,
     * not to the bundled copy, whichever comes first in the model.
     */
    @Test
    void bundledCopyDoesNotTakeTopLevelComponentPath() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");
        model.setMetadata(metadata);

        ArtifactCoords x = ArtifactCoords.of("com.fasterxml.jackson.core", "jackson-core", "2.22.0");
        PackageComponent bundled = new PackageComponent(x, null, null, List.of(), List.of());
        model.addComponent(new PackageComponent(ArtifactCoords.of("org.keycloak", "admin-cli", "1.0"),
                "bin/client/admin-cli-1.0.jar", "aaa", List.of(), List.of(bundled)));
        model.addComponent(new PackageComponent(x, "lib/jackson-core-2.22.0.jar", "bbb", List.of(), List.of()));

        Bom bom = new BomRenderer().render(model);

        Component topLevel = bom.getComponents().stream()
                .filter(c -> "jackson-core".equals(c.getName())).findFirst()
                .orElseThrow(() -> new AssertionError("top-level jackson-core missing"));
        assertEquals("lib/jackson-core-2.22.0.jar", topLevel.getEvidence().getOccurrences().get(0).getLocation());
        Component nested = bom.getComponents().stream()
                .filter(c -> "admin-cli".equals(c.getName())).findFirst().orElseThrow()
                .getComponents().get(0);
        assertTrue(nested.getEvidence() == null || nested.getEvidence().getOccurrences() == null
                || nested.getEvidence().getOccurrences().isEmpty(),
                "the bundled copy has no file of its own");
    }

    @Test
    void topLevelGetsLeafEntryAndBundledCopyNone() {
        // x ships top-level (dependencies known: none) and bundled in a shaded
        // jar (dependencies unknown); the renderer gives the copies unique bom-refs.
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");
        model.setMetadata(metadata);

        ArtifactCoords x = ArtifactCoords.of("com.example", "x", "1.0");
        PackageComponent bundled = new PackageComponent(x, null, null, List.of(), List.of(), false);
        model.addComponent(new PackageComponent(ArtifactCoords.of("org.example", "shaded", "1.0"),
                "lib/shaded-1.0.jar", "aaa", List.of(), List.of(bundled)));
        model.addComponent(new PackageComponent(x, "lib/x-1.0.jar", "bbb", List.of(), List.of()));

        Bom bom = new BomRenderer().render(model);

        Component shaded = bom.getComponents().stream()
                .filter(c -> "shaded".equals(c.getName())).findFirst().orElseThrow();
        assertEquals("pkg:maven/com.example/x@1.0#2", shaded.getComponents().get(0).getBomRef());
        List<Dependency> xEntries = bom.getDependencies().stream()
                .filter(d -> d.getRef().startsWith("pkg:maven/com.example/x@1.0"))
                .toList();
        assertEquals(List.of("pkg:maven/com.example/x@1.0"), xEntries.stream().map(Dependency::getRef).toList(),
                "the top-level x gets an entry; the bundled copy, whose dependencies are unknown, none");
        assertTrue(xEntries.get(0).getDependencies() == null || xEntries.get(0).getDependencies().isEmpty(),
                "x depends on nothing, so the entry is a leaf");
        assertTrue(bom.getDependencies().stream()
                .flatMap(d -> d.getDependencies() == null ? Stream.empty() : d.getDependencies().stream())
                .noneMatch(d -> d.getRef().endsWith("#2")),
                "nothing depends on the bundled copy");
    }

    /** A model of {@code org.example:my-app:1.0.0} with the given top-level components. */
    private static AssemblyComponents modelOf(List<AssemblyComponent> components) {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");
        model.setMetadata(metadata);
        components.forEach(model::addComponent);
        return model;
    }

    /** The top-level component named {@code name}; fails if there is none. */
    private static Component topLevel(Bom bom, String name) {
        return bom.getComponents().stream().filter(c -> name.equals(c.getName())).findFirst().orElseThrow();
    }

    /** Every dependency entry's sorted children, by the entry's ref. */
    private static Map<String, List<String>> dependencyMap(Bom bom) {
        Map<String, List<String>> map = new HashMap<>();
        for (Dependency d : bom.getDependencies()) {
            map.put(d.getRef(), d.getDependencies() == null ? List.of()
                    : d.getDependencies().stream().map(Dependency::getRef).sorted().toList());
        }
        return map;
    }

    private static final String MAIN_REF = "pkg:maven/org.example/my-app@1.0.0";
    private static final ArtifactCoords X = ArtifactCoords.of("com.example", "x", "1.0");
    private static final ArtifactCoords Y = ArtifactCoords.of("com.example", "y", "1.0");
    private static final ArtifactCoords SHADED = ArtifactCoords.of("org.a", "shaded", "1.0");
    private static final ArtifactCoords WAR = ArtifactCoords.of("org.z", "war", "1.0");

    @Test
    void edgesConnectSpecificCopies() {
        // top level y -> x; a war ships its own y -> x
        PackageComponent topX = PackageComponent.of(X, "lib/x.jar", "hx");
        PackageComponent topY = PackageComponent.of(Y, "lib/y.jar", "hy");
        PackageComponent warX = PackageComponent.of(X, "web/war/WEB-INF/lib/x.jar", "hx");
        PackageComponent warY = PackageComponent.of(Y, "web/war/WEB-INF/lib/y.jar", "hy");
        PackageComponent war = new PackageComponent(WAR, "web/war/", null, List.of(), List.of(warX, warY));
        AssemblyComponents model = modelOf(List.of(topX, topY, war));
        model.addDependencyEdge(new DependencyEdge(topY.id(), topX.id()));
        model.addDependencyEdge(new DependencyEdge(warY.id(), warX.id()));

        RenderedBom rendered = new BomRenderer().renderWithRefs(model);

        String x = X.toPurl().toString(), y = Y.toPurl().toString();
        assertEquals(x, rendered.bomRefs().get(topX.id()));
        assertEquals(x + "#2", rendered.bomRefs().get(warX.id()));
        Map<String, List<String>> deps = dependencyMap(rendered.bom());
        assertEquals(List.of(x), deps.get(y));
        assertEquals(List.of(x + "#2"), deps.get(y + "#2"));
        assertEquals(List.of(), deps.get(WAR.toPurl().toString()));
        assertEquals(List.of(y, WAR.toPurl().toString()), deps.get(MAIN_REF), "x is reached through y");
    }

    @Test
    void handBuiltModelWithoutEdgesKeepsPlainRefsAtTopLevel() {
        // x top-level; a shaded jar bundling x (dependencies unknown)
        PackageComponent shaded = new PackageComponent(SHADED, "lib/shaded.jar", "hs", List.of(),
                List.of(PackageComponent.of(X, null, null, false)), false);
        AssemblyComponents model = modelOf(List.of(shaded, PackageComponent.of(X, "lib/x.jar", "hx", false)));

        Bom bom = new BomRenderer().render(model);

        String x = X.toPurl().toString();
        assertEquals(x, topLevel(bom, "x").getBomRef());
        assertEquals(x + "#2", topLevel(bom, "shaded").getComponents().get(0).getBomRef());
        Map<String, List<String>> deps = dependencyMap(bom);
        assertFalse(deps.containsKey(x));
        assertFalse(deps.containsKey(x + "#2"));
        assertEquals(List.of(x, SHADED.toPurl().toString()), deps.get(MAIN_REF));
    }

    @Test
    void edgeToEitherTopLevelOccurrenceResolvesToTheMergedComponent() {
        PackageComponent x1 = PackageComponent.of(X, "lib/x.jar", "hx");
        PackageComponent x2 = PackageComponent.of(X, "ext/x.jar", "hx");
        PackageComponent y = PackageComponent.of(Y, "lib/y.jar", "hy");
        AssemblyComponents model = modelOf(List.of(x1, x2, y));
        model.addDependencyEdge(new DependencyEdge(y.id(), x2.id()));

        RenderedBom rendered = new BomRenderer().renderWithRefs(model);

        String x = X.toPurl().toString();
        assertEquals(x, rendered.bomRefs().get(x1.id()));
        assertEquals(x, rendered.bomRefs().get(x2.id()));
        assertEquals(List.of(x), dependencyMap(rendered.bom()).get(Y.toPurl().toString()));
    }

    @Test
    void edgeWithUnknownIdIsSkipped() {
        PackageComponent y = PackageComponent.of(Y, "lib/y.jar", "hy");
        AssemblyComponents model = modelOf(List.of(y));
        model.addDependencyEdge(new DependencyEdge(y.id(), ComponentId.generate()));

        Map<String, List<String>> deps = dependencyMap(new BomRenderer().render(model));

        assertEquals(List.of(), deps.get(Y.toPurl().toString()));
    }

    @Test
    void mainComponentBomRefNotDuplicatedInComponents() {
        ArtifactCoords appCoords = ArtifactCoords.of("org.example", "my-app", "1.0.0");
        PackageComponent appComp = PackageComponent.of(appCoords, "lib/my-app-1.0.0.jar", "hash1");
        AssemblyComponents model = modelOf(List.of(appComp));

        Bom bom = new BomRenderer().render(model);

        Component main = bom.getMetadata().getComponent();
        assertNotNull(main);
        String mainRef = main.getBomRef();
        assertNotNull(mainRef);

        Component topComp = topLevel(bom, "my-app");
        assertNotNull(topComp);

        assertNotEquals(mainRef, topComp.getBomRef(),
                "Component in components[] must have a unique bom-ref distinct from metadata.component");
        assertEquals(mainRef + "#2", topComp.getBomRef());
    }
}
