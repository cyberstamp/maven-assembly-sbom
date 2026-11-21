package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SbomGeneratorTest {

    @TempDir
    Path tempDir;

    @Test
    void filterRetainsComponentWithMatchingOccurrencePath() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        addOccurrence(comp, "lib/lib-a-1.0.jar");

        Bom result = filterSbom(List.of(comp),
                Set.of("lib/lib-a-1.0.jar"), Set.of(), "sha256", null);

        assertEquals(1, result.getComponents().size());
        assertEquals("lib-a", result.getComponents().get(0).getName());
    }

    @Test
    void filterRemovesComponentWithNonMatchingOccurrencePath() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        addOccurrence(comp, "lib/lib-a-1.0.jar");

        Bom result = filterSbom(List.of(comp),
                Set.of("other/path.jar"), Set.of(), "sha256", null);

        assertTrue(result.getComponents().isEmpty());
    }

    @Test
    void filterRetainsComponentWithOccurrenceMatchingPrefixedPath() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        addOccurrence(comp, "WEB-INF/lib/lib-a-1.0.jar");

        Bom result = filterSbom(List.of(comp),
                Set.of("web/app.war/WEB-INF/lib/lib-a-1.0.jar"),
                Set.of(), "sha256", "web/app.war/");

        assertEquals(1, result.getComponents().size());
    }

    @Test
    void filterRetainsComponentWithEmptyOccurrenceAndParentPrefix() {
        Component comp = createLibrary("upstream-war",
                "pkg:maven/g/upstream-war@1.0");
        addOccurrence(comp, "");

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of(), "sha256", "web/app.war/");

        assertEquals(1, result.getComponents().size());
    }

    @Test
    void filterRemovesEmptyOccurrenceWithoutParentPrefix() {
        Component comp = createLibrary("upstream-war",
                "pkg:maven/g/upstream-war@1.0");
        addOccurrence(comp, "");

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of(), "sha256", null);

        assertTrue(result.getComponents().isEmpty());
    }

    @Test
    void filterRemovesEmptyOccurrenceForFileComponent() {
        Component comp = new Component();
        comp.setType(Component.Type.FILE);
        comp.setName("some-file.txt");
        comp.setBomRef("file:some-file.txt");
        addOccurrence(comp, "");

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of(), "sha256", "web/app.war/");

        assertTrue(result.getComponents().isEmpty());
    }

    @Test
    void filterRetainsNpmComponentWithNonMatchingOccurrences() {
        Component comp = createLibrary("react", "pkg:npm/react@18.0.0");
        comp.setPurl("pkg:npm/react@18.0.0");
        addOccurrence(comp, "node_modules/react/index.js");

        Bom result = filterSbom(List.of(comp),
                Set.of("other.jar"), Set.of(), "sha256", null);

        assertEquals(1, result.getComponents().size(),
                "npm components should survive filtering even if occurrence doesn't match");
    }

    @Test
    void filterRemovesNonNpmComponentWithNonMatchingOccurrences() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        addOccurrence(comp, "lib/lib-a-1.0.jar");

        Bom result = filterSbom(List.of(comp),
                Set.of("other.jar"), Set.of(), "sha256", null);

        assertTrue(result.getComponents().isEmpty());
    }

    @Test
    void filterRetainsComponentWithNoOccurrencesAndNoHashes() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of(), "sha256", null);

        assertEquals(1, result.getComponents().size(),
                "component with no occurrences and no hashes should survive (can't verify)");
    }

    @Test
    void filterRetainsComponentWithMatchingHash() {
        String hash = "aabbccdd";
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of(hash), "sha256", null);

        assertEquals(1, result.getComponents().size());
    }

    @Test
    void filterRemovesComponentWithNonMatchingHashSameAlgorithm() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, "aabbccdd"));

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of("11223344"), "sha256", null);

        assertTrue(result.getComponents().isEmpty());
    }

    @Test
    void filterCorrectsStaleOccurrencePathByHash() {
        String hash = "aabbccdd";
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(comp, "lib/main/lib-a-1.0.jar");

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(comp)));
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of(hash, List.of("lib/lib/main/lib-a-1.0.jar"))),
                null);

        assertEquals(1, result.getComponents().size());
        List<Occurrence> occs = result.getComponents().get(0)
                .getEvidence().getOccurrences();
        assertEquals(1, occs.size());
        assertEquals("lib/lib/main/lib-a-1.0.jar", occs.get(0).getLocation(),
                "stale occurrence should be corrected to actual archive path");
    }

    @Test
    void filterPreservesCorrectOccurrencePath() {
        String hash = "aabbccdd";
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(comp, "lib/lib-a-1.0.jar");

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(comp)));
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of(hash, List.of("lib/lib-a-1.0.jar"))),
                null);

        assertEquals(1, result.getComponents().size());
        assertEquals("lib/lib-a-1.0.jar",
                result.getComponents().get(0).getEvidence()
                        .getOccurrences().get(0).getLocation(),
                "already-correct occurrence should not be changed");
    }

    @Test
    void filterAddsOccurrenceWhenComponentHasNoneButMatchesByHash() {
        String hash = "aabbccdd";
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(comp)));
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of(hash, List.of("lib/lib-a-1.0.jar"))),
                null);

        assertEquals(1, result.getComponents().size());
        List<Occurrence> occs = result.getComponents().get(0)
                .getEvidence().getOccurrences();
        assertEquals(1, occs.size());
        assertEquals("lib/lib-a-1.0.jar", occs.get(0).getLocation(),
                "occurrence should be added from archive path when missing");
    }

    @Test
    void filterCorrectsOccurrenceWithParentPathPrefix() {
        String hash = "aabbccdd";
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(comp, "WEB-INF/lib/lib-a-1.0.jar");

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(comp)));
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of(hash,
                        List.of("web/app.war/WEB-INF/lib/lib-a-1.0.jar"))),
                "web/app.war/");

        assertEquals(1, result.getComponents().size());
        assertEquals("WEB-INF/lib/lib-a-1.0.jar",
                result.getComponents().get(0).getEvidence()
                        .getOccurrences().get(0).getLocation(),
                "occurrence should be relative to parent path prefix");
    }

    @Test
    void filterRejectsStaleOccurrenceWhenHashMatchesOutsideParentScope() {
        String hash = "aabbccdd";
        Component comp = createLibrary("caffeine", "pkg:maven/g/caffeine@3.2");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(comp, "WEB-INF/lib/caffeine-3.2.jar");

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(comp)));
        // Hash matches a file at lib/ (top-level), NOT under web/app.war/
        List<FileEntry> entries = new ArrayList<>();
        entries.add(new FileEntry("web/app.war/WEB-INF/lib/other.jar", null));
        entries.add(new FileEntry("lib/caffeine-3.2.jar", hash));
        ArchiveIndex index = ArchiveIndex.of(entries, null, "sha256");
        Bom result = SbomGenerator.filterSbomByArchive(sbom, index,
                "web/app.war/");

        assertTrue(result.getComponents().isEmpty(),
                "component whose hash matches outside parent scope should be filtered out");
    }

    @Test
    void filterRetainsScopedComponentWhenHashExistsAtMultiplePaths() {
        String hash = "aabbccdd";
        Component comp = createLibrary("jspecify", "pkg:maven/g/jspecify@1.0");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(comp, "WEB-INF/lib/jspecify-1.0.jar");

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(comp)));
        // Same hash exists at top-level AND under the parent scope
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of(hash, List.of("lib/jspecify-1.0.jar",
                        "web/app.war/WEB-INF/lib/jspecify-1.0.jar"))),
                "web/app.war/");

        assertEquals(1, result.getComponents().size(),
                "component should survive when hash matches a path under parent scope");
        assertEquals("WEB-INF/lib/jspecify-1.0.jar",
                result.getComponents().get(0).getEvidence()
                        .getOccurrences().get(0).getLocation(),
                "occurrence should use the scoped path");
    }

    @Test
    void filterRetainsComponentWithHashOfDifferentAlgorithm() {
        Component comp = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        comp.addHash(new Hash(Hash.Algorithm.MD5, "aabbccdd"));

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of("11223344"), "sha256", null);

        assertEquals(1, result.getComponents().size(),
                "component with hash of non-matching algorithm should survive (can't verify)");
    }

    @Test
    void filterPrunesDependenciesToSurvivingRefs() {
        Component surviving = createLibrary("lib-a", "ref-a");
        Component removed = createLibrary("lib-b", "ref-b");
        removed.addHash(new Hash(Hash.Algorithm.SHA_256, "deadbeef"));

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(surviving, removed)));

        Dependency depA = new Dependency("ref-a");
        depA.addDependency(new Dependency("ref-b"));
        Dependency depB = new Dependency("ref-b");
        sbom.addDependency(depA);
        sbom.addDependency(depB);

        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of("otherhash", List.of("other.jar"))), null);

        assertEquals(1, result.getComponents().size());
        assertEquals("lib-a", result.getComponents().get(0).getName());

        assertEquals(1, result.getDependencies().size());
        assertEquals("ref-a", result.getDependencies().get(0).getRef());
        assertTrue(result.getDependencies().get(0).getDependencies() == null
                || result.getDependencies().get(0).getDependencies().isEmpty(),
                "child ref-b should be pruned from dependency children");
    }

    @Test
    void filterReturnsEmptyBomWhenAllComponentsFiltered() {
        Component comp = createLibrary("lib-a", "ref-a");
        comp.addHash(new Hash(Hash.Algorithm.SHA_256, "deadbeef"));

        Bom result = filterSbom(List.of(comp),
                Set.of(), Set.of("otherhash"), "sha256", null);

        assertTrue(result.getComponents().isEmpty());
        assertNull(result.getDependencies());
    }

    @Test
    void filterReturnsUnchangedWhenNoComponents() {
        Bom sbom = new Bom();
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of()), null);
        assertSame(sbom, result);
    }

    @Test
    void filterCollectsBomRefsFromNestedComponents() {
        Component parent = createLibrary("parent", "ref-parent");
        Component child = createLibrary("child", "ref-child");
        parent.setComponents(new ArrayList<>(List.of(child)));

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(parent)));
        Dependency dep = new Dependency("ref-child");
        sbom.addDependency(dep);

        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of()), null);

        assertEquals(1, result.getComponents().size());
        assertNotNull(result.getDependencies());
        assertTrue(result.getDependencies().stream()
                .anyMatch(d -> "ref-child".equals(d.getRef())),
                "nested child bom-ref should be collected as surviving");
    }

    @Test
    void filterRemovesFileComponentWithMatchingPathButDifferentHash() {
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("hawtconfig.json");
        fileComp.setBomRef("file:hawtconfig.json");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, "stale_hash_from_overlay"));
        addOccurrence(fileComp, "hawtconfig.json");

        Bom result = filterSbom(List.of(fileComp),
                Set.of("hawtconfig.json"), Set.of("actual_archive_hash"), "sha256", null);

        assertTrue(result.getComponents().isEmpty(),
                "FILE component whose path matches but hash differs should be filtered out");
    }

    @Test
    void filterRetainsFileComponentWithMatchingPathAndHash() {
        String hash = "matching_hash";
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("hawtconfig.json");
        fileComp.setBomRef("file:hawtconfig.json");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(fileComp, "hawtconfig.json");

        Bom result = filterSbom(List.of(fileComp),
                Set.of("hawtconfig.json"), Set.of(hash), "sha256", null);

        assertEquals(1, result.getComponents().size(),
                "FILE component with matching path and hash should survive filtering");
    }

    @Test
    void filterRetainsFileComponentWithNoHash() {
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("config.xml");
        fileComp.setBomRef("file:config.xml");
        addOccurrence(fileComp, "config.xml");

        Bom result = filterSbom(List.of(fileComp),
                Set.of("config.xml"), Set.of(), "sha256", null);

        assertEquals(1, result.getComponents().size(),
                "FILE component with no hash should survive (can't verify)");
    }

    @Test
    void filterRejectsFileComponentWithScopedOccurrenceButHashOutsideScope() {
        String hash = "aabbccdd";
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("config.json");
        fileComp.setBomRef("file:config.json");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        addOccurrence(fileComp, "config.json");

        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(fileComp)));
        // Hash exists at top-level, but not under the parent scope
        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of(hash,
                        List.of("lib/config.json"),
                        "other", List.of("web/app.war/config.json"))),
                "web/app.war/");

        assertTrue(result.getComponents().isEmpty(),
                "FILE component whose occurrence matches the scope but"
                        + " whose hash only exists outside the scope"
                        + " should be filtered out");
    }

    // ── removeFileComponents ─────────────────────────────────────────────

    @Test
    void removeFileComponentsStripsTopLevelFiles() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("config.xml");
        fileComp.setBomRef("file:config.xml");
        bom.setComponents(new ArrayList<>(List.of(lib, fileComp)));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals("lib-a", bom.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsStripsNestedFiles() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("nested.txt");
        nestedFile.setBomRef("file:nested.txt");
        Component nestedLib = createLibrary("nested-lib", "ref-nested");
        lib.setComponents(new ArrayList<>(List.of(nestedFile, nestedLib)));
        bom.setComponents(new ArrayList<>(List.of(lib)));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, lib.getComponents().size());
        assertEquals("nested-lib", lib.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsCleansDependencyRefs() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("data.bin");
        fileComp.setBomRef("file:data.bin");
        bom.setComponents(new ArrayList<>(List.of(lib, fileComp)));

        Dependency depA = new Dependency("ref-a");
        depA.addDependency(new Dependency("file:data.bin"));
        Dependency depFile = new Dependency("file:data.bin");
        bom.addDependency(depA);
        bom.addDependency(depFile);

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, bom.getDependencies().size());
        assertEquals("ref-a", bom.getDependencies().get(0).getRef());
        assertTrue(bom.getDependencies().get(0).getDependencies() == null
                || bom.getDependencies().get(0).getDependencies().isEmpty());
    }

    @Test
    void removeFileComponentsCleansNestedDependencyRefs() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("deep.bin");
        fileComp.setBomRef("file:deep.bin");
        bom.setComponents(new ArrayList<>(List.of(lib, fileComp)));

        Dependency grandchild = new Dependency("file:deep.bin");
        Dependency child = new Dependency("ref-child");
        child.addDependency(grandchild);
        Dependency root = new Dependency("ref-a");
        root.addDependency(child);
        bom.addDependency(root);

        SbomGenerator.removeFileComponents(bom);

        Dependency surviving = bom.getDependencies().get(0);
        assertEquals("ref-a", surviving.getRef());
        Dependency survivingChild = surviving.getDependencies().get(0);
        assertEquals("ref-child", survivingChild.getRef());
        assertTrue(survivingChild.getDependencies() == null
                || survivingChild.getDependencies().isEmpty(),
                "grandchild file ref should be removed");
    }

    @Test
    void removeFileComponentsNullComponentsIsNoop() {
        Bom bom = new Bom();
        SbomGenerator.removeFileComponents(bom);
        assertNull(bom.getComponents());
    }

    @Test
    void removeFileComponentsEmptyComponentsIsNoop() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>());
        SbomGenerator.removeFileComponents(bom);
        assertTrue(bom.getComponents().isEmpty());
    }

    @Test
    void removeFileComponentsPreservesNonFileComponents() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component app = new Component();
        app.setType(Component.Type.APPLICATION);
        app.setName("my-app");
        app.setBomRef("ref-app");
        bom.setComponents(new ArrayList<>(List.of(lib, app)));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(2, bom.getComponents().size());
    }

    // ── removeFileComponents with unmodifiable lists ───────────────────

    @Test
    void removeFileComponentsHandlesUnmodifiableComponentList() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("config.xml");
        fileComp.setBomRef("file:config.xml");
        bom.setComponents(List.of(lib, fileComp));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals("lib-a", bom.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsHandlesUnmodifiableNestedComponentList() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("nested.txt");
        nestedFile.setBomRef("file:nested.txt");
        Component nestedLib = createLibrary("nested-lib", "ref-nested");
        lib.setComponents(List.of(nestedFile, nestedLib));
        bom.setComponents(List.of(lib));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, lib.getComponents().size());
        assertEquals("nested-lib", lib.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsHandlesUnmodifiableDependencyList() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("data.bin");
        fileComp.setBomRef("file:data.bin");
        bom.setComponents(List.of(lib, fileComp));

        Dependency depA = new Dependency("ref-a");
        depA.addDependency(new Dependency("file:data.bin"));
        Dependency depFile = new Dependency("file:data.bin");
        bom.setDependencies(List.of(depA, depFile));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, bom.getDependencies().size());
        assertEquals("ref-a", bom.getDependencies().get(0).getRef());
    }

    // ── removeTopLevelFilesDuplicatedByNested with unmodifiable lists ──

    @Test
    void removeTopLevelFilesDuplicatedHandlesUnmodifiableLists() {
        String hash = "aabb1122nested";
        Bom bom = new Bom();

        Component topFile = new Component();
        topFile.setType(Component.Type.FILE);
        topFile.setName("chunk.js");
        topFile.setBomRef("file:web/app.war/chunk.js");
        topFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("chunk.js");
        nestedFile.setBomRef("file:web/app.war/chunk.js");
        nestedFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component parent = createLibrary("app-war", "pkg:maven/g/app-war@1.0");
        parent.setComponents(List.of(nestedFile));

        bom.setComponents(List.of(topFile, parent));

        SbomGenerator.removeTopLevelFilesDuplicatedByNested(bom, "sha256");

        assertEquals(1, bom.getComponents().size());
        assertEquals("app-war", bom.getComponents().get(0).getName());
    }

    // ── replaceFileComponentsWithLibraries with unmodifiable lists ─────

    @Test
    void replaceFileComponentsHandlesUnmodifiableLists() {
        String hash = "aabbccdd11223344";
        Bom bom = new Bom();

        Component lib = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        lib.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("lib-a-1.0.jar");
        fileComp.setBomRef("file:lib/lib-a-1.0.jar");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        bom.setComponents(List.of(lib, fileComp));
        bom.setDependencies(List.of(
                new Dependency("pkg:maven/g/lib-a@1.0"),
                new Dependency("file:lib/lib-a-1.0.jar")));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size());
        assertEquals("lib-a", bom.getComponents().get(0).getName());
    }

    // ── replaceFileComponentsWithLibraries ───────────────────────────────

    @Test
    void replaceNoFileComponentsLeavesUnchanged() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        lib.addHash(new Hash(Hash.Algorithm.SHA_256, "aabb"));
        bom.setComponents(new ArrayList<>(List.of(lib)));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size());
        assertEquals("lib-a", bom.getComponents().get(0).getName());
    }

    @Test
    void replaceFileComponentWithNoMatchingLibraryHashNotReplaced() {
        Bom bom = new Bom();
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("unknown.jar");
        fileComp.setBomRef("file:lib/unknown.jar");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, "aabb"));
        bom.setComponents(new ArrayList<>(List.of(fileComp)));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size());
        assertEquals("unknown.jar", bom.getComponents().get(0).getName());
    }

    @Test
    void replaceNullComponentsIsNoop() {
        Bom bom = new Bom();
        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");
        assertNull(bom.getComponents());
    }

    @Test
    void replaceFileComponentAlreadyReferencedByLibraryIsDeduplicated() {
        String hash = "aabbccdd11223344";
        Bom bom = new Bom();

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("guava-33.jar");
        fileComp.setBomRef("file:lib/guava-33.jar");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component libComp = createLibrary("guava", "pkg:maven/g/guava@33");
        libComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        bom.setComponents(new ArrayList<>(List.of(fileComp, libComp)));

        Dependency rootDep = new Dependency("root");
        rootDep.addDependency(new Dependency("file:lib/guava-33.jar"));
        rootDep.addDependency(new Dependency("pkg:maven/g/guava@33"));
        bom.addDependency(rootDep);
        bom.addDependency(new Dependency("file:lib/guava-33.jar"));
        bom.addDependency(new Dependency("pkg:maven/g/guava@33"));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size());
        assertEquals("guava", bom.getComponents().get(0).getName());

        Dependency root = bom.getDependencies().stream()
                .filter(d -> "root".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(root);
        long libRefCount = root.getDependencies().stream()
                .filter(d -> "pkg:maven/g/guava@33".equals(d.getRef()))
                .count();
        assertEquals(1, libRefCount,
                "library ref should appear exactly once in dependsOn (no duplicate)");
    }

    @Test
    void replaceFileComponentHashAlgorithmMismatchNotReplaced() {
        String hash = "aabbccdd";
        Bom bom = new Bom();

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("lib.jar");
        fileComp.setBomRef("file:lib/lib.jar");
        fileComp.addHash(new Hash(Hash.Algorithm.MD5, hash));

        Component libComp = createLibrary("lib", "pkg:maven/g/lib@1.0");
        libComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        bom.setComponents(new ArrayList<>(List.of(fileComp, libComp)));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(2, bom.getComponents().size(),
                "file component with different hash algorithm should not be replaced");
    }

    @Test
    void replaceFileComponentMatchesNestedLibraryByHash() {
        String hash = "aabbccdd11223344";
        Bom bom = new Bom();

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("caffeine-3.2.3.jar");
        fileComp.setBomRef("file:WEB-INF/lib/caffeine-3.2.3.jar");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component parentComp = createLibrary("parent-war", "pkg:maven/g/parent@1.0");
        Component nestedLib = createLibrary("caffeine", "pkg:maven/g/caffeine@3.2.3");
        nestedLib.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        parentComp.setComponents(new ArrayList<>(List.of(nestedLib)));

        bom.setComponents(new ArrayList<>(List.of(fileComp, parentComp)));

        Dependency rootDep = new Dependency("root");
        rootDep.addDependency(new Dependency("file:WEB-INF/lib/caffeine-3.2.3.jar"));
        bom.addDependency(rootDep);
        bom.addDependency(new Dependency("file:WEB-INF/lib/caffeine-3.2.3.jar"));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size(),
                "file component should be removed when matching nested library hash");
        assertEquals("parent-war", bom.getComponents().get(0).getName());

        Dependency root = bom.getDependencies().stream()
                .filter(d -> "root".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(root);
        assertTrue(root.getDependencies().stream()
                .anyMatch(d -> "pkg:maven/g/caffeine@3.2.3".equals(d.getRef())),
                "dependsOn should be updated to use nested library ref");
    }

    @Test
    void replaceFileComponentMatchesDeeplyNestedLibraryByHash() {
        String hash = "deep1122334455";
        Bom bom = new Bom();

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("deep-lib-1.0.jar");
        fileComp.setBomRef("file:WEB-INF/lib/deep-lib-1.0.jar");
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component grandchild = createLibrary("deep-lib", "pkg:maven/g/deep-lib@1.0");
        grandchild.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component child = createLibrary("inner-war", "pkg:maven/g/inner-war@1.0");
        child.setComponents(new ArrayList<>(List.of(grandchild)));

        Component parent = createLibrary("outer-war", "pkg:maven/g/outer-war@1.0");
        parent.setComponents(new ArrayList<>(List.of(child)));

        bom.setComponents(new ArrayList<>(List.of(fileComp, parent)));

        Dependency rootDep = new Dependency("root");
        rootDep.addDependency(new Dependency("file:WEB-INF/lib/deep-lib-1.0.jar"));
        bom.addDependency(rootDep);
        bom.addDependency(new Dependency("file:WEB-INF/lib/deep-lib-1.0.jar"));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size(),
                "file component should be removed when matching deeply nested library hash");
        assertEquals("outer-war", bom.getComponents().get(0).getName());

        Dependency root = bom.getDependencies().stream()
                .filter(d -> "root".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(root);
        assertTrue(root.getDependencies().stream()
                .anyMatch(d -> "pkg:maven/g/deep-lib@1.0".equals(d.getRef())),
                "dependsOn should be updated to use deeply nested library ref");
    }

    @Test
    void removeTopLevelFilesDuplicatedByNestedFile() {
        String hash = "aabb1122nested";
        Bom bom = new Bom();

        Component topFile = new Component();
        topFile.setType(Component.Type.FILE);
        topFile.setName("chunk.js");
        topFile.setBomRef("file:web/app.war/chunk.js");
        topFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("chunk.js");
        nestedFile.setBomRef("file:web/app.war/chunk.js");
        nestedFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component parent = createLibrary("app-war", "pkg:maven/g/app-war@1.0");
        parent.setComponents(new ArrayList<>(List.of(nestedFile)));

        bom.setComponents(new ArrayList<>(List.of(topFile, parent)));

        SbomGenerator.removeTopLevelFilesDuplicatedByNested(bom, "sha256");

        assertEquals(1, bom.getComponents().size(),
                "top-level file should be removed when nested file has same hash");
        assertEquals("app-war", bom.getComponents().get(0).getName());
    }

    @Test
    void removeTopLevelFilesDuplicatedByNestedPreservesDependencyEntries() {
        String hash = "aabb1122nested";
        Bom bom = new Bom();

        Component topFile = new Component();
        topFile.setType(Component.Type.FILE);
        topFile.setName("chunk.js");
        topFile.setBomRef("file:web/app.war/static/js/chunk.js");
        topFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("chunk.js");
        nestedFile.setBomRef("file:web/app.war/static/js/chunk.js");
        nestedFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component innerWar = createLibrary("inner-war", "pkg:maven/g/inner-war@1.0");
        innerWar.setComponents(new ArrayList<>(List.of(nestedFile)));

        Component outerWar = createLibrary("outer-war", "pkg:maven/g/outer-war@1.0");
        outerWar.setComponents(new ArrayList<>(List.of(innerWar)));

        bom.setComponents(new ArrayList<>(List.of(topFile, outerWar)));
        bom.addDependency(new Dependency("file:web/app.war/static/js/chunk.js"));

        SbomGenerator.removeTopLevelFilesDuplicatedByNested(bom, "sha256");

        assertEquals(1, bom.getComponents().size(),
                "top-level file should be removed");
        assertEquals("outer-war", bom.getComponents().get(0).getName());

        assertNotNull(bom.getDependencies());
        assertTrue(bom.getDependencies().stream()
                .anyMatch(d -> "file:web/app.war/static/js/chunk.js".equals(d.getRef())),
                "dependency entry should be preserved because nested component uses the same bom-ref");
    }

    @Test
    void removeTopLevelFilesDuplicatedCleansChildDependencyRefs() {
        String hash = "childdeprefs123";
        Bom bom = new Bom();

        Component topFile = new Component();
        topFile.setType(Component.Type.FILE);
        topFile.setName("app.js");
        topFile.setBomRef("file:web/app.war/static/app.js");
        topFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("app.js");
        nestedFile.setBomRef("file:static/app.js");
        nestedFile.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component parent = createLibrary("app-war", "pkg:maven/g/app-war@1.0");
        parent.setComponents(new ArrayList<>(List.of(nestedFile)));

        bom.setComponents(new ArrayList<>(List.of(topFile, parent)));

        // Top-level dep whose child references the file that will be removed
        Dependency parentDep = new Dependency("pkg:maven/g/app-war@1.0");
        parentDep.addDependency(new Dependency("file:web/app.war/static/app.js"));
        parentDep.addDependency(new Dependency("pkg:maven/g/other@1.0"));
        bom.addDependency(parentDep);

        SbomGenerator.removeTopLevelFilesDuplicatedByNested(bom, "sha256");

        assertEquals(1, bom.getComponents().size(),
                "top-level file should be removed");

        Dependency survivingDep = bom.getDependencies().stream()
                .filter(d -> "pkg:maven/g/app-war@1.0".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(survivingDep);
        assertEquals(1, survivingDep.getDependencies().size(),
                "child dependency ref to removed file should be cleaned up");
        assertEquals("pkg:maven/g/other@1.0",
                survivingDep.getDependencies().get(0).getRef());
    }

    @Test
    void removeTopLevelFilesKeepsNonDuplicatedFiles() {
        Bom bom = new Bom();

        Component topFile = new Component();
        topFile.setType(Component.Type.FILE);
        topFile.setName("config.xml");
        topFile.setBomRef("file:config.xml");
        topFile.addHash(new Hash(Hash.Algorithm.SHA_256, "uniquehash"));

        Component lib = createLibrary("lib-a", "pkg:maven/g/lib-a@1.0");
        bom.setComponents(new ArrayList<>(List.of(topFile, lib)));

        SbomGenerator.removeTopLevelFilesDuplicatedByNested(bom, "sha256");

        assertEquals(2, bom.getComponents().size(),
                "non-duplicated file should not be removed");
    }

    @Test
    void parseExternalBomsNullReturnsEmpty() {
        List<Bom> result = SbomGenerator.parseExternalBoms(null, tempDir);
        assertTrue(result.isEmpty());
    }

    @Test
    void parseExternalBomsBlankReturnsEmpty() {
        List<Bom> result = SbomGenerator.parseExternalBoms("  ", tempDir);
        assertTrue(result.isEmpty());
    }

    @Test
    void parseExternalBomsSingleValidFile() throws Exception {
        Bom bom = new Bom();
        bom.addComponent(createLibrary("lib-a", "ref-a"));
        Path bomFile = tempDir.resolve("bom.cdx.json");
        BomWriter.writeJson(bom, bomFile, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                bomFile.toString(), null);

        assertEquals(1, result.size());
        assertNotNull(result.get(0).getComponents());
        assertEquals(1, result.get(0).getComponents().size());
    }

    @Test
    void parseExternalBomsMultipleCommasSeparatedFiles() throws Exception {
        Bom bom1 = new Bom();
        bom1.addComponent(createLibrary("lib-a", "ref-a"));
        Path file1 = tempDir.resolve("bom1.cdx.json");
        BomWriter.writeJson(bom1, file1, false);

        Bom bom2 = new Bom();
        bom2.addComponent(createLibrary("lib-b", "ref-b"));
        Path file2 = tempDir.resolve("bom2.cdx.json");
        BomWriter.writeJson(bom2, file2, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                file1 + " , " + file2, null);

        assertEquals(2, result.size());
    }

    @Test
    void parseExternalBomsMissingFileSkipped() {
        List<Bom> result = SbomGenerator.parseExternalBoms(
                "/nonexistent/bom.cdx.json", null);
        assertTrue(result.isEmpty());
    }

    @Test
    void parseExternalBomsRelativePathResolvedAgainstBaseDir() throws Exception {
        Bom bom = new Bom();
        bom.addComponent(createLibrary("lib-a", "ref-a"));
        Path bomFile = tempDir.resolve("sbom.cdx.json");
        BomWriter.writeJson(bom, bomFile, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                "sbom.cdx.json", tempDir);

        assertEquals(1, result.size());
    }

    @Test
    void parseExternalBomsEmptyEntriesSkipped() throws Exception {
        Bom bom = new Bom();
        bom.addComponent(createLibrary("lib-a", "ref-a"));
        Path bomFile = tempDir.resolve("bom.cdx.json");
        BomWriter.writeJson(bom, bomFile, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                "," + bomFile + ",,", null);

        assertEquals(1, result.size());
    }

    private static Component createLibrary(String name, String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(bomRef);
        return comp;
    }

    private static void addOccurrence(Component comp, String location) {
        Evidence evidence = comp.getEvidence();
        if (evidence == null) {
            evidence = new Evidence();
            comp.setEvidence(evidence);
        }
        Occurrence occ = new Occurrence();
        occ.setLocation(location);
        evidence.addOccurrence(occ);
    }

    private static ArchiveIndex buildIndex(
            Map<String, List<String>> hashToPath) {
        List<FileEntry> entries = new ArrayList<>();
        for (var e : hashToPath.entrySet()) {
            for (String path : e.getValue()) {
                entries.add(new FileEntry(path, e.getKey()));
            }
        }
        return ArchiveIndex.of(entries, null, "sha256");
    }

    private static Bom filterSbom(List<Component> components,
            Set<String> archivePaths, Set<String> archiveHashes,
            String normalizedAlg, String parentPathPrefix) {
        List<FileEntry> entries = new ArrayList<>();
        for (String path : archivePaths) {
            entries.add(new FileEntry(path, null));
        }
        for (String hash : archiveHashes) {
            entries.add(new FileEntry(
                    "__hash_shim_" + hash, hash));
        }
        ArchiveIndex index = ArchiveIndex.of(entries, null, normalizedAlg);
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(components));
        return SbomGenerator.filterSbomByArchive(sbom, index,
                parentPathPrefix);
    }

    /**
     * Models the artemis distribution: the console war's own SBOM nests its
     * WEB-INF/lib jars under a wrapper with an empty occurrence, but the
     * distribution excluded one of them from the unpacked war.
     */
    private static Bom warSbomWithShippedAndExcludedJar(Component shipped, Component excluded) {
        Component wrapper = createLibrary("console-war", "ref-wrapper");
        addOccurrence(wrapper, "");
        wrapper.setComponents(new ArrayList<>(List.of(shipped, excluded)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(wrapper)));
        Dependency wrapperDep = new Dependency("ref-wrapper");
        wrapperDep.addDependency(new Dependency(shipped.getBomRef()));
        wrapperDep.addDependency(new Dependency(excluded.getBomRef()));
        sbom.addDependency(wrapperDep);
        sbom.addDependency(new Dependency(shipped.getBomRef()));
        sbom.addDependency(new Dependency(excluded.getBomRef()));
        return sbom;
    }

    @Test
    void filterRemovesNestedComponentNotInArchive() {
        Component shipped = createLibrary("jspecify", "ref-shipped");
        shipped.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        addOccurrence(shipped, "WEB-INF/lib/jspecify-1.0.0.jar");
        Component excluded = createLibrary("caffeine", "ref-excluded");
        excluded.addHash(new Hash(Hash.Algorithm.SHA_256, "bb22"));
        addOccurrence(excluded, "WEB-INF/lib/caffeine-3.2.3.jar");

        Bom result = SbomGenerator.filterSbomByArchive(warSbomWithShippedAndExcludedJar(shipped, excluded),
                buildIndex(Map.of("aa11", List.of("web/console.war/WEB-INF/lib/jspecify-1.0.0.jar"))),
                "web/console.war/");

        Component wrapper = result.getComponents().get(0);
        assertEquals(List.of("jspecify"), wrapper.getComponents().stream().map(Component::getName).toList());
        assertTrue(result.getDependencies().stream().noneMatch(d -> "ref-excluded".equals(d.getRef())),
                "dependency entry of the dropped component is pruned");
        Dependency wrapperDep = result.getDependencies().stream()
                .filter(d -> "ref-wrapper".equals(d.getRef())).findFirst().orElseThrow();
        assertEquals(List.of("ref-shipped"),
                wrapperDep.getDependencies().stream().map(Dependency::getRef).toList());
    }

    @Test
    void filterCorrectsNestedComponentOccurrenceByHash() {
        Component moved = createLibrary("jspecify", "ref-moved");
        moved.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        addOccurrence(moved, "WEB-INF/lib/old-name.jar");
        Component other = createLibrary("other", "ref-other");
        addOccurrence(other, "WEB-INF/lib/other.jar");

        Bom result = SbomGenerator.filterSbomByArchive(warSbomWithShippedAndExcludedJar(moved, other),
                buildIndex(Map.of("aa11", List.of("web/console.war/WEB-INF/lib/jspecify-1.0.0.jar"))),
                "web/console.war/");

        Component kept = result.getComponents().get(0).getComponents().get(0);
        assertEquals("WEB-INF/lib/jspecify-1.0.0.jar", kept.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void filterKeepsNestedComponentsWithoutOccurrencesOrHashes() {
        // under an unpacked war, a nested component carrying neither has
        // nothing to verify and is kept, while its sibling naming a jar the
        // archive lacks is dropped (proving the nested check ran)
        Component excluded = createLibrary("excluded", "ref-excluded");
        excluded.addHash(new Hash(Hash.Algorithm.SHA_256, "dd44"));
        addOccurrence(excluded, "WEB-INF/lib/excluded.jar");
        Component war = createLibrary("console", "ref-war");
        addOccurrence(war, "");
        war.setComponents(new ArrayList<>(List.of(createLibrary("jcip", "ref-jcip"), excluded)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(war)));

        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of("cc33", List.of("web/console.war/WEB-INF/lib/nimbus.jar"))),
                "web/console.war/");

        assertEquals(List.of("jcip"),
                result.getComponents().get(0).getComponents().stream().map(Component::getName).toList());
    }

    /** wrapper ("") > app.war ("app.war/") > inner.jar, as an ear-like SBOM lays out an unpacked war */
    private static Bom sbomWithUnpackedSubArchive() {
        Component inner = createLibrary("inner", "ref-inner");
        inner.addHash(new Hash(Hash.Algorithm.SHA_256, "dd44"));
        addOccurrence(inner, "app.war/WEB-INF/lib/inner.jar");
        Component war = createLibrary("app", "ref-app");
        addOccurrence(war, "app.war/");
        war.setComponents(new ArrayList<>(List.of(inner)));
        Component wrapper = createLibrary("wrapper", "ref-wrapper");
        addOccurrence(wrapper, "");
        wrapper.setComponents(new ArrayList<>(List.of(war)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(wrapper)));
        return sbom;
    }

    @Test
    void filterKeepsNestedComponentWithDirectoryOccurrenceWhenArchiveHasFilesUnderIt() {
        Bom result = SbomGenerator.filterSbomByArchive(sbomWithUnpackedSubArchive(),
                buildIndex(Map.of("dd44", List.of("ear/app.war/WEB-INF/lib/inner.jar"))), "ear/");

        Component war = result.getComponents().get(0).getComponents().get(0);
        assertEquals("app", war.getName());
        assertEquals(List.of("inner"), war.getComponents().stream().map(Component::getName).toList());
    }

    @Test
    void filterKeepsTopLevelComponentWithDirectoryOccurrenceWhenArchiveHasFilesUnderIt() {
        Component war = createLibrary("app", "ref-app");
        addOccurrence(war, "app.war/");
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(war)));

        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of("dd44", List.of("ear/app.war/WEB-INF/lib/inner.jar"))), "ear/");

        assertEquals(1, result.getComponents().size());
    }

    @Test
    void filterDropsComponentWithDirectoryOccurrenceWhenArchiveHasNothingUnderIt() {
        Bom result = SbomGenerator.filterSbomByArchive(sbomWithUnpackedSubArchive(),
                buildIndex(Map.of("ee55", List.of("ear/other.war/WEB-INF/lib/other.jar"))), "ear/");

        assertTrue(result.getComponents().get(0).getComponents().isEmpty(),
                "a directory the archive has no files under is not shipped");
    }

    @Test
    void filterChecksNestedComponentsOnUnscopedIndex() {
        // the unscoped path used for configured external SBOMs
        Component kept = createLibrary("kept", "ref-kept");
        kept.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        addOccurrence(kept, "lib/kept.jar");
        Component gone = createLibrary("gone", "ref-gone");
        gone.addHash(new Hash(Hash.Algorithm.SHA_256, "bb22"));
        addOccurrence(gone, "lib/gone.jar");
        Component npm = createLibrary("react", "pkg:npm/react@18.0.0");
        npm.setPurl("pkg:npm/react@18.0.0");
        addOccurrence(npm, "node_modules/react/index.js");
        Component file = createLibrary("config.json", "file:config.json");
        file.setType(Component.Type.FILE);
        file.addHash(new Hash(Hash.Algorithm.SHA_256, "cc33"));
        addOccurrence(file, "conf/config.json");
        Component parent = createLibrary("app", "ref-app");
        addOccurrence(parent, "lib/");
        parent.setComponents(new ArrayList<>(List.of(kept, gone, npm, file)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(parent)));

        Bom result = SbomGenerator.filterSbomByArchive(sbom, buildIndex(Map.of(
                "aa11", List.of("lib/kept.jar"),
                "cc33", List.of("conf/config.json"))), null);

        assertEquals(List.of("kept", "react", "config.json"),
                result.getComponents().get(0).getComponents().stream().map(Component::getName).toList());
    }

    @Test
    void rejectedExternalComponentIsNotMergedEvenThoughItsHashIsInTheArchive() {
        Component rejected = createLibrary("h2", "pkg:maven/com.h2database/h2@2.3");
        rejected.setPurl("pkg:maven/com.h2database/h2@2.3");
        rejected.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        Component kept = createLibrary("react", "pkg:npm/react@18.0.0");
        kept.setPurl("pkg:npm/react@18.0.0");
        kept.addHash(new Hash(Hash.Algorithm.SHA_256, "bb22"));
        Bom external = new Bom();
        external.setComponents(new ArrayList<>(List.of(rejected, kept)));
        external.addDependency(new Dependency("pkg:maven/com.h2database/h2@2.3"));
        external.addDependency(new Dependency("pkg:npm/react@18.0.0"));

        Set<Component> rejectedSet = Collections.newSetFromMap(new IdentityHashMap<>());
        rejectedSet.add(rejected);

        Bom result = SbomGenerator.filterExternalSbom(external,
                buildIndex(Map.of("aa11", List.of("lib/h2-2.4.jar"), "bb22", List.of("web/react.js"))),
                rejectedSet, identitySet());

        assertEquals(List.of("react"), result.getComponents().stream().map(Component::getName).toList());
        assertEquals(List.of("pkg:npm/react@18.0.0"),
                result.getDependencies().stream().map(Dependency::getRef).toList());
    }

    @Test
    void nestedRejectedExternalComponentIsRemovedWithItsDependencyReferences() {
        // the owner jar is packed, so only the rejection removes its nested h2
        Component rejected = createLibrary("h2", "pkg:maven/com.h2database/h2@2.3");
        rejected.setPurl("pkg:maven/com.h2database/h2@2.3");
        rejected.addHash(new Hash(Hash.Algorithm.SHA_256, "bb22"));
        Component sibling = createLibrary("jcip", "ref-jcip");
        Component owner = createLibrary("app", "ref-app");
        owner.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        addOccurrence(owner, "lib/app.jar");
        owner.setComponents(new ArrayList<>(List.of(rejected, sibling)));
        Bom external = new Bom();
        external.setComponents(new ArrayList<>(List.of(owner)));
        Dependency ownerDeps = new Dependency("ref-app");
        ownerDeps.addDependency(new Dependency("pkg:maven/com.h2database/h2@2.3"));
        ownerDeps.addDependency(new Dependency("ref-jcip"));
        external.addDependency(ownerDeps);
        external.addDependency(new Dependency("pkg:maven/com.h2database/h2@2.3"));

        Bom result = SbomGenerator.filterExternalSbom(external,
                buildIndex(Map.of("aa11", List.of("lib/app.jar"), "bb22", List.of("lib/h2-2.4.jar"))),
                identitySet(rejected), identitySet(owner));

        Component kept = result.getComponents().get(0);
        assertEquals(List.of("jcip"), kept.getComponents().stream().map(Component::getName).toList());
        assertEquals(List.of("ref-app"), result.getDependencies().stream().map(Dependency::getRef).toList());
        assertEquals(List.of("ref-jcip"), result.getDependencies().get(0).getDependencies().stream()
                .map(Dependency::getRef).toList());
    }

    @Test
    void filterKeepsNestedContentsOfPackedJar() {
        // a fat jar's SBOM describes its internals: BOOT-INF/lib jars and
        // shaded artifacts listed with their original hash are not files of
        // the assembly, yet they ship inside it
        Component bootLib = createLibrary("boot-lib", "ref-boot-lib");
        bootLib.addHash(new Hash(Hash.Algorithm.SHA_256, "bb22"));
        addOccurrence(bootLib, "BOOT-INF/lib/boot-lib-1.0.jar");
        Component shaded = createLibrary("shaded", "ref-shaded");
        shaded.addHash(new Hash(Hash.Algorithm.SHA_256, "cc33"));
        Component fat = createLibrary("fat", "ref-fat");
        fat.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        addOccurrence(fat, "lib/fat-1.0.jar");
        fat.setComponents(new ArrayList<>(List.of(bootLib, shaded)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(fat)));

        Bom result = SbomGenerator.filterSbomByArchive(sbom,
                buildIndex(Map.of("aa11", List.of("lib/fat-1.0.jar"))), null);

        assertEquals(List.of("boot-lib", "shaded"),
                result.getComponents().get(0).getComponents().stream().map(Component::getName).toList());
    }

    private static Set<Component> identitySet(Component... components) {
        Set<Component> set = Collections.newSetFromMap(new IdentityHashMap<>());
        set.addAll(List.of(components));
        return set;
    }

    @Test
    void matchedDescendantOfRejectedExternalComponentIsKept() {
        // C's claim was rejected, but its nested D matched another file of the
        // archive: D must not vanish with C
        Component d = createLibrary("react", "pkg:npm/react@18.0.0");
        d.setPurl("pkg:npm/react@18.0.0");
        d.addHash(new Hash(Hash.Algorithm.SHA_256, "bb22"));
        addOccurrence(d, "web/react.js");
        Component bundledOfC = createLibrary("bundled", "ref-bundled");
        Component c = createLibrary("h2", "pkg:maven/com.h2database/h2@2.3");
        c.setPurl("pkg:maven/com.h2database/h2@2.3");
        c.addHash(new Hash(Hash.Algorithm.SHA_256, "aa11"));
        c.setComponents(new ArrayList<>(List.of(d, bundledOfC)));
        Bom external = new Bom();
        external.setComponents(new ArrayList<>(List.of(c)));

        Bom result = SbomGenerator.filterExternalSbom(external,
                buildIndex(Map.of("aa11", List.of("lib/h2-2.4.jar"), "bb22", List.of("web/react.js"))),
                identitySet(c), identitySet(d));

        assertEquals(List.of("react"), result.getComponents().stream().map(Component::getName).toList(),
                "the matched descendant is lifted; the rejected component and its unmatched internals go");
    }
}
