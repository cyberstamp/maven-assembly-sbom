package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;

/**
 * Final steps on a rendered BOM, after anything merged into it: makes the
 * component bom-refs unique and sorts the dependency entries.
 */
final class BomFinalizer {

    private BomFinalizer() {
    }

    /**
     * Makes component bom-refs unique. Of the components sharing a bom-ref,
     * the first one met (top-level components before nested ones) keeps it,
     * except that when a dependency entry exists for the bom-ref it goes to
     * the first one met whose dependencies are known: the dependency graph
     * was built on the shared bom-ref, so it keeps describing the instance it
     * can describe. The others get {@code #2}, {@code #3}, ... appended in the
     * order met.
     *
     * <p>
     * A renamed copy is another instance of the same artifact, e.g. a
     * dependency bundled in a shaded jar or shipped inside a war. It gets a
     * copy of the original's dependency entry, since the artifact's
     * dependencies are the same, unless its own dependencies are unknown: an
     * entry would then declare them as none. A component whose entry lists the
     * artifact also lists the renamed copies nested in it, which are its own;
     * copies nested in other components are not added to its entry.
     * </p>
     *
     * @param bom the BOM to update
     * @param dependenciesUnknown components whose dependencies are unknown,
     *        compared by identity
     */
    static void deduplicateBomRefs(Bom bom, Set<Component> dependenciesUnknown) {
        List<Component> ordered = new ArrayList<>();
        if (bom.getComponents() != null) {
            collectInDeduplicationOrder(bom.getComponents(), ordered);
        }
        Component main = bom.getMetadata() == null ? null : bom.getMetadata().getComponent();
        if (main != null && main.getComponents() != null) {
            collectInDeduplicationOrder(main.getComponents(), ordered);
        }
        Map<String, List<Component>> instancesByRef = new LinkedHashMap<>();
        for (Component comp : ordered) {
            if (comp.getBomRef() != null) {
                instancesByRef.computeIfAbsent(comp.getBomRef(), k -> new ArrayList<>()).add(comp);
            }
        }
        Set<String> taken = new HashSet<>(instancesByRef.keySet());
        Set<String> refsWithEntry = new HashSet<>();
        if (bom.getDependencies() != null) {
            for (Dependency dep : bom.getDependencies()) {
                refsWithEntry.add(dep.getRef());
            }
        }
        // renamed copies with their original bom-ref; a list, since Component
        // equality is by value and identical copies are what is renamed
        List<Map.Entry<Component, String>> originalRefs = new ArrayList<>();
        for (Map.Entry<String, List<Component>> e : instancesByRef.entrySet()) {
            List<Component> instances = e.getValue();
            if (instances.size() < 2) {
                continue;
            }
            // the entry built on the shared bom-ref describes an instance whose
            // dependencies are known; without an entry, the first one met keeps it
            Component holder = !refsWithEntry.contains(e.getKey()) ? instances.get(0)
                    : instances.stream()
                            .filter(c -> !dependenciesUnknown.contains(c))
                            .findFirst().orElse(instances.get(0));
            int suffix = 2;
            for (Component comp : instances) {
                if (comp == holder) {
                    continue;
                }
                String unique = e.getKey() + "#" + suffix;
                while (!taken.add(unique)) {
                    unique = e.getKey() + "#" + ++suffix;
                }
                comp.setBomRef(unique);
                originalRefs.add(Map.entry(comp, e.getKey()));
            }
        }
        if (originalRefs.isEmpty() || bom.getDependencies() == null) {
            return;
        }
        Map<String, Dependency> entriesByRef = new HashMap<>();
        for (Dependency dep : bom.getDependencies()) {
            entriesByRef.putIfAbsent(dep.getRef(), dep);
        }
        for (Map.Entry<Component, String> renamed : originalRefs) {
            Dependency original = entriesByRef.get(renamed.getValue());
            if (original == null || dependenciesUnknown.contains(renamed.getKey())) {
                continue;
            }
            Dependency clone = new Dependency(renamed.getKey().getBomRef());
            if (original.getDependencies() != null) {
                for (Dependency child : original.getDependencies()) {
                    clone.addDependency(new Dependency(child.getRef()));
                }
            }
            bom.getDependencies().add(clone);
        }
        addNestedRenamedCopies(bom, ordered, main, originalRefs);
        repointMainToTopLevelCopies(bom, main, instancesByRef);
    }

    /**
     * Points the main component's entry at the top-level copies of an
     * artifact. The renderer makes the main component depend on what ships at
     * the top level, so its edge to a bom-ref means the top-level copy, which
     * may have been renamed while a nested copy kept the bom-ref. An edge to a
     * bom-ref with no top-level copy is left as it is.
     */
    private static void repointMainToTopLevelCopies(Bom bom, Component main,
            Map<String, List<Component>> instancesByRef) {
        if (main == null || main.getBomRef() == null || bom.getComponents() == null) {
            return;
        }
        Dependency mainEntry = null;
        for (Dependency dep : bom.getDependencies()) {
            if (main.getBomRef().equals(dep.getRef())) {
                mainEntry = dep;
                break;
            }
        }
        if (mainEntry == null || mainEntry.getDependencies() == null) {
            return;
        }
        Set<Component> topLevel = Collections.newSetFromMap(new IdentityHashMap<>());
        topLevel.addAll(bom.getComponents());
        List<Dependency> children = new ArrayList<>();
        Set<String> listed = new HashSet<>();
        for (Dependency child : mainEntry.getDependencies()) {
            List<Component> instances = instancesByRef.getOrDefault(child.getRef(), List.of());
            List<String> topLevelRefs = instances.stream()
                    .filter(topLevel::contains)
                    .map(Component::getBomRef)
                    .toList();
            if (instances.size() < 2 || topLevelRefs.isEmpty()) {
                if (listed.add(child.getRef())) {
                    children.add(child);
                }
                continue;
            }
            for (String ref : topLevelRefs) {
                if (listed.add(ref)) {
                    children.add(new Dependency(ref));
                }
            }
        }
        mainEntry.setDependencies(children);
    }

    /**
     * Sorts the dependency entries, and each entry's children, by ref. The
     * renderer emits them sorted, but merging SBOMs and making bom-refs unique
     * append entries and children afterwards.
     */
    static void sortDependencies(Bom bom) {
        if (bom.getDependencies() == null) {
            return;
        }
        Comparator<Dependency> byRef = Comparator.comparing(Dependency::getRef,
                Comparator.nullsFirst(Comparator.naturalOrder()));
        bom.getDependencies().sort(byRef);
        for (Dependency dep : bom.getDependencies()) {
            if (dep.getDependencies() != null) {
                dep.getDependencies().sort(byRef);
            }
        }
    }

    /**
     * Lists a top-level-first, level-by-level order: each list's components
     * before any of their sub-components.
     */
    private static void collectInDeduplicationOrder(List<Component> components, List<Component> ordered) {
        ordered.addAll(components);
        for (Component comp : components) {
            if (comp.getComponents() != null) {
                collectInDeduplicationOrder(comp.getComponents(), ordered);
            }
        }
    }

    /**
     * For each dependency entry listing an artifact that has renamed copies,
     * adds the copies nested in the entry's own component.
     */
    private static void addNestedRenamedCopies(Bom bom, List<Component> ordered, Component main,
            List<Map.Entry<Component, String>> originalRefs) {
        Map<Component, String> originalRefOf = new IdentityHashMap<>();
        for (Map.Entry<Component, String> renamed : originalRefs) {
            originalRefOf.put(renamed.getKey(), renamed.getValue());
        }
        Map<String, Component> componentsByRef = new HashMap<>();
        for (Component comp : ordered) {
            componentsByRef.put(comp.getBomRef(), comp);
        }
        if (main != null && main.getBomRef() != null) {
            componentsByRef.putIfAbsent(main.getBomRef(), main);
        }
        for (Dependency dep : bom.getDependencies()) {
            Component owner = componentsByRef.get(dep.getRef());
            if (owner == null || owner.getComponents() == null || dep.getDependencies() == null) {
                continue;
            }
            Map<String, List<String>> nestedCopies = new HashMap<>();
            collectRenamedDescendants(owner.getComponents(), originalRefOf, nestedCopies);
            if (nestedCopies.isEmpty()) {
                continue;
            }
            Set<String> listed = new HashSet<>();
            for (Dependency child : dep.getDependencies()) {
                listed.add(child.getRef());
            }
            for (Dependency child : List.copyOf(dep.getDependencies())) {
                for (String copy : nestedCopies.getOrDefault(child.getRef(), List.of())) {
                    if (listed.add(copy)) {
                        dep.addDependency(new Dependency(copy));
                    }
                }
            }
        }
    }

    private static void collectRenamedDescendants(List<Component> components, Map<Component, String> originalRefOf,
            Map<String, List<String>> copiesByOriginalRef) {
        for (Component comp : components) {
            String original = originalRefOf.get(comp);
            if (original != null) {
                copiesByOriginalRef.computeIfAbsent(original, k -> new ArrayList<>()).add(comp.getBomRef());
            }
            if (comp.getComponents() != null) {
                collectRenamedDescendants(comp.getComponents(), originalRefOf, copiesByOriginalRef);
            }
        }
    }
}
