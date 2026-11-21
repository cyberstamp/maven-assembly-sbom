package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.junit.jupiter.api.Test;

class BomFinalizerTest {

    @Test
    void deduplicateNoDuplicatesUnchanged() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(
                createLibrary("a", "ref-a"),
                createLibrary("b", "ref-b"))));

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

        assertEquals("ref-a", bom.getComponents().get(0).getBomRef());
        assertEquals("ref-b", bom.getComponents().get(1).getBomRef());
    }

    @Test
    void deduplicateRenamesDuplicateBomRef() {
        Bom bom = new Bom();
        Component first = createLibrary("a-v1", "ref-a");
        Component second = createLibrary("a-v2", "ref-a");
        bom.setComponents(new ArrayList<>(List.of(first, second)));

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

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

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

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

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

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
    void deduplicateDoesNotAddRenamedCopyToDependents() {
        // b depends on the artifact a; the second a is a copy bundled elsewhere,
        // which b does not depend on
        Bom bom = new Bom();
        Component first = createLibrary("a1", "ref-a");
        Component second = createLibrary("a2", "ref-a");
        bom.setComponents(new ArrayList<>(List.of(first, second, createLibrary("b", "ref-b"))));
        Dependency b = new Dependency("ref-b");
        b.addDependency(new Dependency("ref-a"));
        bom.addDependency(b);

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

        assertEquals(List.of("ref-a"), bom.getDependencies().get(0).getDependencies().stream()
                .map(Dependency::getRef).toList());
    }

    @Test
    void deduplicateGivesNoEntryToRenamedCopyWithUnknownDependencies() {
        Bom bom = new Bom();
        Component first = createLibrary("a1", "ref-a");
        Component bundled = createLibrary("a2", "ref-a");
        bom.setComponents(new ArrayList<>(List.of(first, bundled)));
        bom.addDependency(new Dependency("ref-a"));

        BomFinalizer.deduplicateBomRefs(bom, identitySet(bundled));

        assertEquals("ref-a#2", bundled.getBomRef());
        assertEquals(List.of("ref-a"), bom.getDependencies().stream().map(Dependency::getRef).toList(),
                "an entry would declare the bundled copy's unknown dependencies as none");
    }

    @Test
    void deduplicateKeepsFirstMetHolderWhenNoEntryDescribesTheArtifact() {
        // jcip is bundled in a top-level jar (dependencies unknown) and, from
        // a merged SBOM, in a jar nested deeper (not rendered by this tool);
        // neither has an entry, so there is nothing to keep with a known copy
        Component topBundled = createLibrary("jcip", "ref-jcip");
        Component top = createLibrary("nimbus-10.10", "ref-nimbus-10.10");
        top.setComponents(new ArrayList<>(List.of(topBundled)));
        Component mergedBundled = createLibrary("jcip", "ref-jcip");
        Component nested = createLibrary("nimbus-10.6", "ref-nimbus-10.6");
        nested.setComponents(new ArrayList<>(List.of(mergedBundled)));
        Component war = createLibrary("war", "ref-war");
        war.setComponents(new ArrayList<>(List.of(nested)));
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(top, war)));
        bom.addDependency(new Dependency("ref-war"));

        BomFinalizer.deduplicateBomRefs(bom, identitySet(topBundled));

        assertEquals("ref-jcip", topBundled.getBomRef());
        assertEquals("ref-jcip#2", mergedBundled.getBomRef());
    }

    @Test
    void deduplicateKeepsTopLevelCopyReachableFromMain() {
        // x ships at the top level, identified from its pom.properties
        // (dependencies unknown), and inside an unpacked overlay, matched by
        // Maven (dependencies known, nested without a dependency edge)
        Component topX = createLibrary("x-top", "ref-x");
        Component overlayX = createLibrary("x-overlay", "ref-x");
        Component overlay = createLibrary("overlay", "ref-overlay");
        overlay.setComponents(new ArrayList<>(List.of(overlayX)));
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(overlay, topX)));
        Metadata meta = new Metadata();
        meta.setComponent(createLibrary("app", "ref-app"));
        bom.setMetadata(meta);
        Dependency main = new Dependency("ref-app");
        main.addDependency(new Dependency("ref-overlay"));
        main.addDependency(new Dependency("ref-x"));
        bom.addDependency(main);
        Dependency x = new Dependency("ref-x");
        x.addDependency(new Dependency("ref-y"));
        bom.addDependency(x);
        bom.addDependency(new Dependency("ref-overlay"));

        BomFinalizer.deduplicateBomRefs(bom, identitySet(topX));

        // the entry built from Maven stays with the copy whose dependencies are known
        assertEquals("ref-x", overlayX.getBomRef());
        assertEquals("ref-x#2", topX.getBomRef());
        // main's edge was made for the top-level copy and follows it
        assertEquals(List.of("ref-overlay", "ref-x#2"),
                main.getDependencies().stream().map(Dependency::getRef).toList());
        assertTrue(bom.getDependencies().stream().noneMatch(d -> "ref-x#2".equals(d.getRef())),
                "the top-level copy's dependencies are unknown");
    }

    @Test
    void deduplicateLeavesMainEdgeToRefWithoutTopLevelCopy() {
        // main lists a bom-ref (e.g. from a merged SBOM) whose copies are all nested
        Component a = createLibrary("a-in-p", "ref-a");
        Component b = createLibrary("a-in-q", "ref-a");
        Component p = createLibrary("p", "ref-p");
        p.setComponents(new ArrayList<>(List.of(a)));
        Component q = createLibrary("q", "ref-q");
        q.setComponents(new ArrayList<>(List.of(b)));
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(p, q)));
        Metadata meta = new Metadata();
        meta.setComponent(createLibrary("app", "ref-app"));
        bom.setMetadata(meta);
        Dependency main = new Dependency("ref-app");
        main.addDependency(new Dependency("ref-a"));
        bom.addDependency(main);

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

        assertEquals(List.of("ref-a"), main.getDependencies().stream().map(Dependency::getRef).toList());
    }

    @Test
    void sortDependenciesOrdersEntriesAndTheirChildrenByRef() {
        // entries cloned or imported after rendering are appended unsorted
        Bom bom = new Bom();
        Dependency b = new Dependency("ref-b");
        b.addDependency(new Dependency("ref-z"));
        b.addDependency(new Dependency("ref-a#2"));
        b.addDependency(new Dependency("ref-a"));
        bom.addDependency(b);
        bom.addDependency(new Dependency("ref-a#2"));
        bom.addDependency(new Dependency("ref-a"));

        BomFinalizer.sortDependencies(bom);

        assertEquals(List.of("ref-a", "ref-a#2", "ref-b"),
                bom.getDependencies().stream().map(Dependency::getRef).toList());
        assertEquals(List.of("ref-a", "ref-a#2", "ref-z"),
                bom.getDependencies().get(2).getDependencies().stream().map(Dependency::getRef).toList());
    }

    @Test
    void deduplicateHandlesNestedComponentDuplicates() {
        Bom bom = new Bom();
        Component parent = createLibrary("parent", "ref-parent");
        Component nested1 = createLibrary("child1", "ref-dup");
        Component nested2 = createLibrary("child2", "ref-dup");
        parent.setComponents(new ArrayList<>(List.of(nested1, nested2)));
        bom.setComponents(new ArrayList<>(List.of(parent)));

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

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

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

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

        BomFinalizer.deduplicateBomRefs(bom, Set.of());

        assertEquals("ref-dup", topDup.getBomRef(),
                "top-level component should keep the clean bom-ref");
        assertEquals("ref-dup#2", nestedDup.getBomRef(),
                "nested component should get the #2 suffix");
    }

    @Test
    void deduplicateNoComponentsIsNoop() {
        Bom bom = new Bom();
        BomFinalizer.deduplicateBomRefs(bom, Set.of());
        assertNull(bom.getComponents());
    }

    private static Component createLibrary(String name, String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(bomRef);
        return comp;
    }

    private static Set<Component> identitySet(Component... components) {
        Set<Component> set = Collections.newSetFromMap(new IdentityHashMap<>());
        set.addAll(List.of(components));
        return set;
    }
}
