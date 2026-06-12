package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class BomMergerTest {

    @Test
    void mergeAddsComponentsAsNestedUnderParent() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "lib-a", "1.0", "pkg:maven/org.a/lib-a@1.0"));

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/lib-a@1.0", source);

        Component parent = target.getComponents().get(0);
        assertNotNull(parent.getComponents(), "parent should have nested components");
        assertEquals(2, parent.getComponents().size());
        assertEquals("lodash", parent.getComponents().get(0).getName(),
                "nested components should be sorted by name");
        assertEquals("react", parent.getComponents().get(1).getName());
    }

    @Test
    void mergeImportsDependencyEntries() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "lib-a", "1.0", "pkg:maven/org.a/lib-a@1.0"));
        target.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Dependency reactDep = new Dependency("pkg:npm/react@18.3.1");
        reactDep.addDependency(new Dependency("pkg:npm/loose-envify@1.4.0"));

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createLibrary(null, "loose-envify", "1.4.0", "pkg:npm/loose-envify@1.4.0"));
        source.addDependency(reactDep);
        source.addDependency(new Dependency("pkg:npm/loose-envify@1.4.0"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/lib-a@1.0", source);

        assertEquals(3, target.getDependencies().size(),
                "target should have original dep + 2 imported deps");
        assertTrue(target.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/react@18.3.1".equals(d.getRef())),
                "react dependency should be imported");
    }

    @Test
    void mergeDoesNotCreateCrossEcosystemDependencyEdges() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0"));
        target.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        Dependency mainDep = target.getDependencies().stream()
                .filter(d -> "pkg:maven/com.example/app@1.0".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(mainDep);
        if (mainDep.getDependencies() != null) {
            assertFalse(mainDep.getDependencies().stream()
                    .anyMatch(d -> "pkg:npm/react@18.3.1".equals(d.getRef())),
                    "no cross-ecosystem edge from main to npm component");
        }
    }

    @Test
    void mergeUnderMainComponent() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0");

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/com.example/app@1.0", source);

        Component main = target.getMetadata().getComponent();
        assertNotNull(main.getComponents(), "main component should have nested components");
        assertEquals(1, main.getComponents().size());
        assertEquals("react", main.getComponents().get(0).getName());
    }

    @Test
    void mergePreservesExistingNestedComponents() {
        Component existingNested = createLibrary("org.b", "nested-lib", "2.0",
                "pkg:maven/org.b/nested-lib@2.0");
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        parent.addComponent(existingNested);

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(2, parent.getComponents().size(),
                "existing nested component should be preserved");
        assertTrue(parent.getComponents().stream()
                .anyMatch(c -> "nested-lib".equals(c.getName())));
        assertTrue(parent.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())));
    }

    @Test
    void mergeWithUnknownParentBomRefThrows() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0");

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        assertThrows(IllegalArgumentException.class,
                () -> BomMerger.mergeUnder(target, "pkg:maven/nonexistent@1.0", source));
    }

    @Test
    void mergeWithEmptySourceBomIsNoOp() {
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Bom source = new Bom();

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertNull(parent.getComponents(), "no nested components should be added");
    }

    @Test
    void addBomReferenceCreatesExternalRef() {
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        BomMerger.addBomReference(target, "pkg:maven/org.a/war@1.0",
                "web/console.war/bom.cdx.json");

        List<ExternalReference> refs = parent.getExternalReferences();
        assertNotNull(refs, "parent should have external references");
        assertEquals(1, refs.size());
        assertEquals(ExternalReference.Type.BOM, refs.get(0).getType());
        assertEquals("web/console.war/bom.cdx.json", refs.get(0).getUrl());
    }

    @Test
    void addBomReferenceWithUnknownParentThrows() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0");

        assertThrows(IllegalArgumentException.class,
                () -> BomMerger.addBomReference(target,
                        "pkg:maven/nonexistent@1.0", "bom.cdx.json"));
    }

    @Test
    void findComponentByBomRefSearchesNestedComponents() {
        Component nested = createLibrary("org.b", "nested", "2.0",
                "pkg:maven/org.b/nested@2.0");
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        parent.addComponent(nested);

        Bom bom = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Component found = BomMerger.findComponentByBomRef(bom, "pkg:maven/org.b/nested@2.0");
        assertNotNull(found, "should find nested component");
        assertEquals("nested", found.getName());
    }

    @Test
    void duplicateDependencyRefsNotImported() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "war-a", "1.0", "pkg:maven/org.a/war-a@1.0"),
                createLibrary("org.b", "war-b", "1.0", "pkg:maven/org.b/war-b@1.0"));
        target.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Dependency sharedDep = new Dependency("pkg:npm/lodash@4.17.21");
        Dependency reactDep = new Dependency("pkg:npm/react@18.3.1");
        reactDep.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));

        Bom sourceA = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));
        sourceA.addDependency(reactDep);
        sourceA.addDependency(sharedDep);

        Bom sourceB = buildSourceBom(
                createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));
        sourceB.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war-a@1.0", sourceA);
        BomMerger.mergeUnder(target, "pkg:maven/org.b/war-b@1.0", sourceB);

        long lodashCount = target.getDependencies().stream()
                .filter(d -> "pkg:npm/lodash@4.17.21".equals(d.getRef()))
                .count();
        assertEquals(1, lodashCount,
                "shared dependency ref should appear only once");
        assertEquals(3, target.getDependencies().size(),
                "target should have original + react + lodash (no duplicate)");
    }

    @Test
    void mergeDeduplicatesNestedComponentAndMergesHashes() {
        Component nimbus = createLibrary("com.nimbusds", "nimbus-jose-jwt", "10.6",
                "pkg:maven/com.nimbusds/nimbus-jose-jwt@10.6");
        nimbus.addHash(new Hash(Hash.Algorithm.SHA_256, "abc123"));
        nimbus.setEvidence(evidenceWithOccurrence(
                "web/console.war/WEB-INF/lib/nimbus-jose-jwt-10.6.jar"));

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.addComponent(nimbus);
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        Component nimbusFromSbom = createLibrary("com.nimbusds", "nimbus-jose-jwt", "10.6",
                "pkg:maven/com.nimbusds/nimbus-jose-jwt@10.6?type=jar");
        nimbusFromSbom.addHash(new Hash("MD5", "md5hash"));
        nimbusFromSbom.addHash(new Hash("SHA-1", "sha1hash"));
        nimbusFromSbom.addHash(new Hash(Hash.Algorithm.SHA_256, "abc123"));

        Bom source = buildSourceBom(nimbusFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(1, war.getComponents().size(),
                "duplicate should be merged, not added");
        Component merged = war.getComponents().get(0);
        assertEquals("nimbus-jose-jwt", merged.getName());
        assertEquals(3, merged.getHashes().size(),
                "hashes from SBOM should be merged into existing");
        assertNotNull(merged.getEvidence());
        assertEquals(1, merged.getEvidence().getOccurrences().size());
        assertEquals("web/console.war/WEB-INF/lib/nimbus-jose-jwt-10.6.jar",
                merged.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void mergeMigratesOccurrencesFromTopLevelToNested() {
        Component jspecify = createLibrary("org.jspecify", "jspecify", "1.0.0",
                "pkg:maven/org.jspecify/jspecify@1.0.0");
        Evidence jspecEvidence = new Evidence();
        jspecEvidence.addOccurrence(occurrence("lib/jspecify-1.0.0.jar"));
        jspecEvidence.addOccurrence(occurrence(
                "web/console.war/WEB-INF/lib/jspecify-1.0.0.jar"));
        jspecify.setEvidence(jspecEvidence);

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war, jspecify);

        Component jspecFromSbom = createLibrary("org.jspecify", "jspecify", "1.0.0",
                "pkg:maven/org.jspecify/jspecify@1.0.0?type=jar");
        Bom source = buildSourceBom(jspecFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(1, jspecify.getEvidence().getOccurrences().size());
        assertEquals("lib/jspecify-1.0.0.jar",
                jspecify.getEvidence().getOccurrences().get(0).getLocation());
        assertTrue(target.getComponents().contains(jspecify),
                "jspecify should remain at top-level");

        assertNotNull(war.getComponents());
        assertEquals(1, war.getComponents().size());
        Component nestedJspec = war.getComponents().get(0);
        assertEquals("jspecify", nestedJspec.getName());
        assertNotNull(nestedJspec.getEvidence());
        assertEquals(1, nestedJspec.getEvidence().getOccurrences().size());
        assertEquals("web/console.war/WEB-INF/lib/jspecify-1.0.0.jar",
                nestedJspec.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void mergeKeepsTopLevelAfterOccurrenceMigration() {
        Component shared = createLibrary("org.x", "shared-lib", "1.0",
                "pkg:maven/org.x/shared-lib@1.0");
        Evidence evidence = new Evidence();
        evidence.addOccurrence(occurrence("lib/shared-lib-1.0.jar"));
        evidence.addOccurrence(occurrence(
                "web/console.war/WEB-INF/lib/shared-lib-1.0.jar"));
        shared.setEvidence(evidence);

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war, shared);
        assertEquals(2, target.getComponents().size());

        Component sharedFromSbom = createLibrary("org.x", "shared-lib", "1.0",
                "pkg:maven/org.x/shared-lib@1.0?type=jar");
        Bom source = buildSourceBom(sharedFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(2, target.getComponents().size(),
                "top-level should be preserved (it exists at lib/ too)");
        assertEquals(1, shared.getEvidence().getOccurrences().size());
        assertEquals("lib/shared-lib-1.0.jar",
                shared.getEvidence().getOccurrences().get(0).getLocation());

        assertNotNull(war.getComponents());
        assertEquals(1, war.getComponents().size());
        assertEquals("web/console.war/WEB-INF/lib/shared-lib-1.0.jar",
                war.getComponents().get(0).getEvidence()
                        .getOccurrences().get(0).getLocation());
    }

    @Test
    void mergeRemovesTopLevelWhenAllOccurrencesMigrated() {
        Component warOnly = createLibrary("org.x", "war-only-lib", "1.0",
                "pkg:maven/org.x/war-only-lib@1.0");
        warOnly.setEvidence(evidenceWithOccurrence(
                "web/console.war/WEB-INF/lib/war-only-lib-1.0.jar"));

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war, warOnly);
        assertEquals(2, target.getComponents().size());

        Component warOnlyFromSbom = createLibrary("org.x", "war-only-lib", "1.0",
                "pkg:maven/org.x/war-only-lib@1.0?type=jar");
        Bom source = buildSourceBom(warOnlyFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(1, target.getComponents().size(),
                "war-only-lib should be removed from top-level");
        assertEquals("war", target.getComponents().get(0).getName());

        assertNotNull(war.getComponents());
        assertEquals(1, war.getComponents().size());
        Component nested = war.getComponents().get(0);
        assertEquals("war-only-lib", nested.getName());
        assertNotNull(nested.getEvidence());
        assertEquals("web/console.war/WEB-INF/lib/war-only-lib-1.0.jar",
                nested.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void mergeWithoutParentPrefixAddsAllAsNested() {
        Component parent = createLibrary("org.a", "lib", "1.0", "pkg:maven/org.a/lib@1.0");
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Bom source = buildSourceBom(
                createLibrary(null, "dep-a", "1.0", "pkg:npm/dep-a@1.0"),
                createLibrary(null, "dep-b", "2.0", "pkg:npm/dep-b@2.0"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/lib@1.0", source);

        assertNotNull(parent.getComponents());
        assertEquals(2, parent.getComponents().size(),
                "all source components should be added as nested");
    }

    @Test
    void mergeMigratesOccurrencesWhenParentHasNoPathPrefix() {
        // Root-level WAR overlay: jspecify is both a project dependency
        // and in the overlay's SBOM. Archive analysis hash-matches it
        // as top-level before the WAR is detected as unpacked at root.
        Component jspecify = createLibrary("org.jspecify", "jspecify", "1.0.0",
                "pkg:maven/org.jspecify/jspecify@1.0.0");
        jspecify.setEvidence(evidenceWithOccurrence(
                "WEB-INF/lib/jspecify-1.0.0.jar"));

        Component war = createLibrary("org.a", "war", "1.0",
                "pkg:maven/org.a/war@1.0?type=war");

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                war, jspecify);

        Component jspecFromSbom = createLibrary("org.jspecify", "jspecify", "1.0.0",
                "pkg:maven/org.jspecify/jspecify@1.0.0?type=jar");
        Bom source = buildSourceBom(jspecFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0?type=war", source);

        // occurrence should migrate from top-level to nested
        assertNotNull(war.getComponents());
        assertEquals(1, war.getComponents().size());
        Component nestedJspec = war.getComponents().get(0);
        assertNotNull(nestedJspec.getEvidence());
        assertEquals("WEB-INF/lib/jspecify-1.0.0.jar",
                nestedJspec.getEvidence().getOccurrences().get(0).getLocation());

        // top-level should have lost its occurrence and been removed
        assertFalse(target.getComponents().contains(jspecify),
                "top-level jspecify should be removed after all occurrences migrated");
    }

    @Test
    void mergeDeduplicateCarriesOverLicensesFromSbom() {
        Component nested = createLibrary("org.x", "lib", "1.0",
                "pkg:maven/org.x/lib@1.0");
        nested.setEvidence(evidenceWithOccurrence(
                "web/console.war/WEB-INF/lib/lib-1.0.jar"));

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.addComponent(nested);
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        Component fromSbom = createLibrary("org.x", "lib", "1.0",
                "pkg:maven/org.x/lib@1.0?type=jar");
        org.cyclonedx.model.License license = new org.cyclonedx.model.License();
        license.setId("Apache-2.0");
        LicenseChoice lc = new LicenseChoice();
        lc.addLicense(license);
        fromSbom.setLicenses(lc);

        Bom source = buildSourceBom(fromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(1, war.getComponents().size());
        assertNotNull(war.getComponents().get(0).getLicenses(),
                "licenses from SBOM should be applied to existing nested component");
    }

    @Test
    void mergeComponentDataDeduplicatesSubComponents() {
        Component child = createLibrary("org.c", "child", "1.0",
                "pkg:maven/org.c/child@1.0");

        Component existing = createLibrary("org.x", "shaded", "1.0",
                "pkg:maven/org.x/shaded@1.0");
        existing.addComponent(child);
        existing.setEvidence(evidenceWithOccurrence(
                "web/console.war/WEB-INF/lib/shaded-1.0.jar"));

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.addComponent(existing);
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        // Source SBOM has same shaded jar with the same sub-component
        Component childFromSbom = createLibrary("org.c", "child", "1.0",
                "pkg:maven/org.c/child@1.0?type=jar");
        Component shadedFromSbom = createLibrary("org.x", "shaded", "1.0",
                "pkg:maven/org.x/shaded@1.0?type=jar");
        shadedFromSbom.addComponent(childFromSbom);

        Bom source = buildSourceBom(shadedFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(1, war.getComponents().size());
        Component merged = war.getComponents().get(0);
        assertEquals(1, merged.getComponents().size(),
                "sub-component should not be duplicated");
        assertEquals("child", merged.getComponents().get(0).getName());
    }

    @Test
    void mergeDeduplicatesAcrossPurlTypeJarVariants() {
        // Existing nested without ?type=jar (our convention)
        Component existing = createLibrary("org.x", "lib", "1.0",
                "pkg:maven/org.x/lib@1.0");
        existing.addHash(new Hash(Hash.Algorithm.SHA_256, "abc"));
        existing.setEvidence(evidenceWithOccurrence(
                "web/console.war/WEB-INF/lib/lib-1.0.jar"));

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.addComponent(existing);
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        // Source SBOM includes ?type=jar (cyclonedx-maven-plugin convention)
        Component fromExternal = createLibrary("org.x", "lib", "1.0",
                "pkg:maven/org.x/lib@1.0?type=jar");
        fromExternal.addHash(new Hash("MD5", "md5hash"));

        Bom source = buildSourceBom(fromExternal);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(1, war.getComponents().size(),
                "PURLs differing only in ?type=jar should be treated as equal");
        assertEquals(2, war.getComponents().get(0).getHashes().size());
    }

    @Test
    void mergeAddsUnmatchedSbomComponentsAsNested() {
        Component kept = createLibrary("org.x", "kept-lib", "1.0",
                "pkg:maven/org.x/kept-lib@1.0");
        kept.setEvidence(evidenceWithOccurrence(
                "web/console.war/WEB-INF/lib/kept-lib-1.0.jar"));

        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.addComponent(kept);
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        Component keptFromSbom = createLibrary("org.x", "kept-lib", "1.0",
                "pkg:maven/org.x/kept-lib@1.0?type=jar");
        Component extraFromSbom = createLibrary("org.x", "extra-lib", "2.0",
                "pkg:maven/org.x/extra-lib@2.0?type=jar");
        Bom source = buildSourceBom(keptFromSbom, extraFromSbom);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(2, war.getComponents().size(),
                "unmatched SBOM components should be added as nested");
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> "kept-lib".equals(c.getName())));
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> "extra-lib".equals(c.getName())));
    }

    @Test
    void mergeDoesNotStripParentOwnOccurrence() {
        Component war = createLibrary("org.a", "war", "1.0",
                "pkg:maven/org.a/war@1.0?type=war");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        // Source SBOM mistakenly lists the WAR itself as a component
        Component warAsSrc = createLibrary("org.a", "war", "1.0",
                "pkg:maven/org.a/war@1.0?type=war");
        Bom source = buildSourceBom(warAsSrc);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0?type=war", source);

        assertNotNull(war.getEvidence());
        assertEquals(1, war.getEvidence().getOccurrences().size(),
                "parent's own occurrence must not be stripped");
        assertEquals("web/console.war/",
                war.getEvidence().getOccurrences().get(0).getLocation());
        assertTrue(target.getComponents().contains(war),
                "parent must not be removed from top-level");
    }

    @Test
    void mergeUnderPrefixesFileBomRefsForUnpackedArchive() {
        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("app.js");
        fileComp.setBomRef("file:static/js/app.js");
        fileComp.setPurl("pkg:generic/app.js");

        Bom source = buildSourceBom(fileComp);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertNotNull(war.getComponents());
        assertEquals(1, war.getComponents().size());
        assertEquals("file:web/console.war/static/js/app.js",
                war.getComponents().get(0).getBomRef(),
                "file bom-ref should be prefixed with parent path");
    }

    @Test
    void mergeUnderPrefixesFileDependencyRefsForUnpackedArchive() {
        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("app.js");
        fileComp.setBomRef("file:static/js/app.js");
        fileComp.setPurl("pkg:generic/app.js");

        Bom source = buildSourceBom(fileComp);
        source.addDependency(new Dependency("file:static/js/app.js"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertTrue(target.getDependencies().stream()
                .anyMatch(d -> "file:web/console.war/static/js/app.js".equals(d.getRef())),
                "file dependency ref should be prefixed with parent path");
        assertFalse(target.getDependencies().stream()
                .anyMatch(d -> "file:static/js/app.js".equals(d.getRef())),
                "original unprefixed ref should not remain");
    }

    @Test
    void mergeUnderDoesNotPrefixMavenBomRefs() {
        Component war = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        war.setEvidence(evidenceWithOccurrence("web/console.war/"));

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", war);

        Component mavenComp = createLibrary("org.x", "lib", "1.0",
                "pkg:maven/org.x/lib@1.0");
        Bom source = buildSourceBom(mavenComp);
        source.addDependency(new Dependency("pkg:maven/org.x/lib@1.0"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        Component nested = war.getComponents().get(0);
        assertEquals("pkg:maven/org.x/lib@1.0", nested.getBomRef(),
                "Maven bom-ref should not be prefixed");
        assertTrue(target.getDependencies().stream()
                .anyMatch(d -> "pkg:maven/org.x/lib@1.0".equals(d.getRef())),
                "Maven dependency ref should not be prefixed");
    }

    @Test
    void mergeUnderSkipsPrefixWhenParentHasNoPathPrefix() {
        Component lib = createLibrary("org.a", "lib", "1.0", "pkg:maven/org.a/lib@1.0");
        // no evidence → no path prefix

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", lib);

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("data.txt");
        fileComp.setBomRef("file:data.txt");
        fileComp.setPurl("pkg:generic/data.txt");

        Bom source = buildSourceBom(fileComp);

        BomMerger.mergeUnder(target, "pkg:maven/org.a/lib@1.0", source);

        assertEquals("file:data.txt", lib.getComponents().get(0).getBomRef(),
                "file bom-ref should not be prefixed when parent has no path prefix");
    }

    @Test
    void normalizeMavenPurlStripsTypeJar() {
        // ?type=jar as only qualifier
        assertEquals("pkg:maven/g/a@1.0",
                BomMerger.normalizeMavenPurl("pkg:maven/g/a@1.0?type=jar"));
        // already normalized
        assertEquals("pkg:maven/g/a@1.0",
                BomMerger.normalizeMavenPurl("pkg:maven/g/a@1.0"));
        // non-jar type preserved
        assertEquals("pkg:maven/g/a@1.0?type=war",
                BomMerger.normalizeMavenPurl("pkg:maven/g/a@1.0?type=war"));
        // ?type=jar as first qualifier with others
        assertEquals("pkg:maven/g/a@1.0?classifier=linux",
                BomMerger.normalizeMavenPurl("pkg:maven/g/a@1.0?type=jar&classifier=linux"));
        // &type=jar as last qualifier
        assertEquals("pkg:maven/g/a@1.0?classifier=linux",
                BomMerger.normalizeMavenPurl("pkg:maven/g/a@1.0?classifier=linux&type=jar"));
        // &type=jar in the middle
        assertEquals("pkg:maven/g/a@1.0?classifier=linux&scope=compile",
                BomMerger.normalizeMavenPurl(
                        "pkg:maven/g/a@1.0?classifier=linux&type=jar&scope=compile"));
        // null and non-maven
        assertNull(BomMerger.normalizeMavenPurl(null));
        assertEquals("pkg:npm/react@18.0",
                BomMerger.normalizeMavenPurl("pkg:npm/react@18.0"));
    }

    private static Evidence evidenceWithOccurrence(String location) {
        Evidence evidence = new Evidence();
        evidence.addOccurrence(occurrence(location));
        return evidence;
    }

    private static Occurrence occurrence(String location) {
        Occurrence occ = new Occurrence();
        occ.setLocation(location);
        return occ;
    }

    private static Bom buildTargetBom(String mainBomRef, Component... components) {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef(mainBomRef);
        metadata.setComponent(main);
        bom.setMetadata(metadata);
        if (components.length > 0) {
            bom.setComponents(new java.util.ArrayList<>(List.of(components)));
        }
        return bom;
    }

    private static Bom buildSourceBom(Component... components) {
        Bom bom = new Bom();
        bom.setComponents(new java.util.ArrayList<>(List.of(components)));
        return bom;
    }

    private static Component createLibrary(String group, String name, String version,
            String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(group);
        comp.setName(name);
        comp.setVersion(version);
        comp.setBomRef(bomRef);
        comp.setPurl(bomRef);
        return comp;
    }
}
