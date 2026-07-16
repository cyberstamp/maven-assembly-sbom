package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SbomGeneratorTest {

    @TempDir
    Path tempDir;

    // ── filterSbomByArchive ─────────────────────────────────────────────

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
                Set.of(), Set.of("otherhash"), "sha256", null);

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
                Set.of(), Set.of(), "sha256", null);
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
                Set.of(), Set.of(), "sha256", null);

        assertEquals(1, result.getComponents().size());
        assertNotNull(result.getDependencies());
        assertTrue(result.getDependencies().stream()
                .anyMatch(d -> "ref-child".equals(d.getRef())),
                "nested child bom-ref should be collected as surviving");
    }

    // ── deduplicateBomRefs ──────────────────────────────────────────────

    @Test
    void deduplicateNoDuplicatesUnchanged() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(
                createLibrary("a", "ref-a"),
                createLibrary("b", "ref-b"))));

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals("ref-a", bom.getComponents().get(0).getBomRef());
        assertEquals("ref-b", bom.getComponents().get(1).getBomRef());
    }

    @Test
    void deduplicateRenamesDuplicateBomRef() {
        Bom bom = new Bom();
        Component first = createLibrary("a-v1", "ref-a");
        Component second = createLibrary("a-v2", "ref-a");
        bom.setComponents(new ArrayList<>(List.of(first, second)));

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals("ref-a", first.getBomRef());
        assertEquals("ref-a#2", second.getBomRef());
    }

    @Test
    void deduplicateHandlesTripleDuplicate() {
        Bom bom = new Bom();
        Component first = createLibrary("a1", "ref-a");
        Component second = createLibrary("a2", "ref-a");
        Component third = createLibrary("a3", "ref-a");
        bom.setComponents(new ArrayList<>(List.of(first, second, third)));

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals("ref-a", first.getBomRef());
        assertEquals("ref-a#2", second.getBomRef());
        assertEquals("ref-a#3", third.getBomRef());
    }

    @Test
    void deduplicateClonesDependencyEntriesForRenamedRefs() {
        Bom bom = new Bom();
        Component first = createLibrary("a1", "ref-a");
        Component second = createLibrary("a2", "ref-a");
        bom.setComponents(new ArrayList<>(List.of(first, second)));

        Dependency dep = new Dependency("ref-a");
        dep.addDependency(new Dependency("ref-child"));
        bom.addDependency(dep);

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals(2, bom.getDependencies().size());
        Dependency cloned = bom.getDependencies().stream()
                .filter(d -> "ref-a#2".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(cloned, "dependency entry should be cloned for renamed ref");
        assertTrue(cloned.getDependencies().stream()
                .anyMatch(d -> "ref-child".equals(d.getRef())),
                "cloned dependency should copy children");
    }

    @Test
    void deduplicateHandlesNestedComponentDuplicates() {
        Bom bom = new Bom();
        Component parent = createLibrary("parent", "ref-parent");
        Component nested1 = createLibrary("child1", "ref-dup");
        Component nested2 = createLibrary("child2", "ref-dup");
        parent.setComponents(new ArrayList<>(List.of(nested1, nested2)));
        bom.setComponents(new ArrayList<>(List.of(parent)));

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals("ref-dup", nested1.getBomRef());
        assertEquals("ref-dup#2", nested2.getBomRef());
    }

    @Test
    void deduplicateHandlesMetadataComponentChildren() {
        Bom bom = new Bom();
        Component top = createLibrary("top", "ref-dup");
        bom.setComponents(new ArrayList<>(List.of(top)));

        Metadata meta = new Metadata();
        Component main = createLibrary("app", "ref-app");
        Component metaNested = createLibrary("meta-child", "ref-dup");
        main.setComponents(new ArrayList<>(List.of(metaNested)));
        meta.setComponent(main);
        bom.setMetadata(meta);

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals("ref-dup", top.getBomRef());
        assertEquals("ref-dup#2", metaNested.getBomRef());
    }

    @Test
    void deduplicateTopLevelKeepsCleanRefOverNested() {
        Bom bom = new Bom();
        Component parentA = createLibrary("a-parent", "ref-parent-a");
        Component nestedDup = createLibrary("dup-nested", "ref-dup");
        parentA.setComponents(new ArrayList<>(List.of(nestedDup)));

        Component topDup = createLibrary("dup-top", "ref-dup");
        // parentA sorts before topDup alphabetically
        bom.setComponents(new ArrayList<>(List.of(parentA, topDup)));

        Dependency dep = new Dependency("ref-dup");
        bom.addDependency(dep);

        SbomGenerator.deduplicateBomRefs(bom);

        assertEquals("ref-dup", topDup.getBomRef(),
                "top-level component should keep the clean bom-ref");
        assertEquals("ref-dup#2", nestedDup.getBomRef(),
                "nested component should get the #2 suffix");
    }

    @Test
    void deduplicateNoComponentsIsNoop() {
        Bom bom = new Bom();
        SbomGenerator.deduplicateBomRefs(bom);
        assertNull(bom.getComponents());
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

    // ── parseExternalBoms ───────────────────────────────────────────────

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

    // ── helpers ──────────────────────────────────────────────────────────

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

    private static Bom filterSbom(List<Component> components,
            Set<String> archivePaths, Set<String> archiveHashes,
            String normalizedAlg, String parentPathPrefix) {
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(components));
        return SbomGenerator.filterSbomByArchive(sbom,
                archivePaths, archiveHashes, normalizedAlg, parentPathPrefix);
    }
}
