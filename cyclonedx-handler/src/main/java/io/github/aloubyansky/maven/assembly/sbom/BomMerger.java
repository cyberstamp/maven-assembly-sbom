package io.github.aloubyansky.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * Merges or links external CycloneDX SBOMs into a target SBOM.
 *
 * <p>
 * This utility supports three integration modes:
 * </p>
 * <ul>
 * <li><b>Merge nested</b> ({@link #mergeUnder}) — imports the source
 * BOM's components as nested sub-components of a parent component in
 * the target BOM. Deduplicates against existing nested components by
 * PURL, migrates occurrences from top-level components whose files
 * fall under the parent's path, and imports dependency entries.
 * PURLs are normalized (redundant {@code ?type=jar} stripped) on
 * incoming components to ensure consistent matching. When the parent
 * is an unpacked archive, {@code file:} bom-refs and dependency refs
 * are prefixed with the parent's archive path so they use
 * distribution-relative paths.</li>
 * <li><b>Merge flat</b> ({@link #mergeFlat}) — imports the source
 * BOM's components into the target BOM's top-level component list
 * and imports its dependency entries.</li>
 * <li><b>Link</b> ({@link #addBomReference}) — adds a CycloneDX
 * {@code externalReference} of type {@code bom} to a parent
 * component, pointing to the SBOM file's location within the
 * archive.</li>
 * </ul>
 */
public final class BomMerger {

    private static final Comparator<Component> COMPONENT_ORDER = BomBuilder.COMPONENT_ORDER;

    private BomMerger() {
    }

    /**
     * Merges the source BOM's components as nested sub-components
     * under the specified parent component in the target BOM.
     *
     * <p>
     * Source components are sorted by group/name/version and appended
     * to the parent's existing nested component list (if any).
     * Dependency entries from the source BOM are imported into the
     * target BOM's top-level dependency section. When the parent is
     * an unpacked archive (has a directory-style occurrence ending
     * with {@code '/'}), {@code file:} bom-refs on source components
     * and imported dependency refs are prefixed with the parent's
     * archive path to produce distribution-relative references.
     * </p>
     *
     * @param targetBom the distribution BOM to merge into
     * @param parentBomRef the {@code bom-ref} of the parent component
     * @param sourceBom the external BOM whose components to import
     */
    public static void mergeUnder(Bom targetBom, String parentBomRef, Bom sourceBom) {
        Component parent = findComponentByBomRef(targetBom, parentBomRef);
        if (parent == null) {
            throw new IllegalArgumentException(
                    "Cannot merge SBOM: parent component with bom-ref '"
                            + parentBomRef + "' not found");
        }
        String parentPathPrefix = getParentPathPrefix(parent);
        nestComponents(targetBom, parent, sourceBom.getComponents(), parentPathPrefix);
        importDependencies(targetBom, sourceBom.getDependencies(), parentPathPrefix);
    }

    /**
     * Merges the source BOM's components into the target BOM's
     * top-level component list, and imports its dependency entries.
     *
     * @param targetBom the BOM to merge into
     * @param sourceBom the external BOM whose components to import
     */
    public static void mergeFlat(Bom targetBom, Bom sourceBom) {
        if (sourceBom.getComponents() != null) {
            List<Component> sorted = new ArrayList<>(sourceBom.getComponents());
            sorted.sort(COMPONENT_ORDER);
            for (Component comp : sorted) {
                normalizePurls(comp);
                targetBom.addComponent(comp);
            }
        }
        importDependencies(targetBom, sourceBom.getDependencies(), null);
    }

    /**
     * Adds a CycloneDX external reference of type {@code bom} to the
     * specified parent component, pointing to the given archive path.
     *
     * <p>
     * If the parent component cannot be found, a warning is logged
     * and no changes are made.
     * </p>
     *
     * @param targetBom the distribution BOM
     * @param parentBomRef the {@code bom-ref} of the parent component
     * @param bomPath the archive-internal path to the SBOM file
     */
    public static void addBomReference(Bom targetBom, String parentBomRef, String bomPath) {
        Component parent = findComponentByBomRef(targetBom, parentBomRef);
        if (parent == null) {
            throw new IllegalArgumentException(
                    "Cannot add BOM reference: parent component with bom-ref '"
                            + parentBomRef + "' not found");
        }
        ExternalReference ref = new ExternalReference();
        ref.setType(ExternalReference.Type.BOM);
        ref.setUrl(bomPath);
        parent.addExternalReference(ref);
    }

    /**
     * Merges source components into the parent's nested component list,
     * deduplicating against existing nested components and migrating
     * occurrences from top-level components when appropriate.
     *
     * <p>
     * For each source component, three cases are handled:
     * </p>
     * <ol>
     * <li>A nested component with the same PURL already exists under the
     * parent (e.g. from archive analysis) — the source's hashes, licenses,
     * and sub-components are merged into the existing component.</li>
     * <li>A top-level component with the same PURL exists and has occurrences
     * under the parent's path prefix — those occurrences are migrated to the
     * source component, which is then added as nested.</li>
     * <li>Otherwise — the source component is added as a new nested
     * component.</li>
     * </ol>
     *
     * @param targetBom the target BOM containing top-level components
     * @param parent the parent component to nest source components under
     * @param components the source components to merge, or {@code null}
     */
    private static void nestComponents(Bom targetBom, Component parent,
            List<Component> components, String parentPathPrefix) {
        if (components == null || components.isEmpty()) {
            return;
        }

        Map<String, Component> existingNestedByPurl = indexByPurl(parent.getComponents());
        Map<String, Component> topLevelByPurl = indexByPurl(targetBom.getComponents());

        List<Component> sorted = new ArrayList<>(components);
        sorted.sort(COMPONENT_ORDER);

        for (Component comp : sorted) {
            normalizePurls(comp);
            prefixFileBomRef(comp, parentPathPrefix);
            String purl = comp.getPurl();

            if (purl != null) {
                Component existingNested = existingNestedByPurl.get(purl);
                if (existingNested != null) {
                    mergeComponentData(existingNested, comp);
                    continue;
                }

                Component topLevel = topLevelByPurl.get(purl);
                if (topLevel != null && topLevel != parent) {
                    migrateOccurrences(topLevel, comp, parentPathPrefix);
                    if (!hasOccurrences(topLevel)) {
                        targetBom.getComponents().remove(topLevel);
                    }
                }
            }

            parent.addComponent(comp);
        }
    }

    private static final String FILE_BOMREF_PREFIX = "file:";

    /**
     * Prefixes a file component's bom-ref with the parent's archive path
     * so it uses distribution-relative paths instead of archive-relative.
     * Only applies to components whose bom-ref starts with {@code "file:"}
     * and only when the parent is an unpacked archive (non-null prefix).
     */
    private static void prefixFileBomRef(Component comp, String parentPathPrefix) {
        if (parentPathPrefix == null) {
            return;
        }
        String bomRef = comp.getBomRef();
        if (bomRef != null && bomRef.startsWith(FILE_BOMREF_PREFIX)) {
            comp.setBomRef(FILE_BOMREF_PREFIX + parentPathPrefix
                    + bomRef.substring(FILE_BOMREF_PREFIX.length()));
        }
    }

    /**
     * Derives the archive directory prefix from the parent component's
     * evidence. Returns the first occurrence location that ends with
     * {@code '/'}, indicating an exploded archive (e.g. {@code "web/console.war/"}).
     *
     * @return the directory prefix, or {@code null} if the parent has
     *         no directory-style occurrence
     */
    static String getParentPathPrefix(Component parent) {
        Evidence evidence = parent.getEvidence();
        if (evidence == null || evidence.getOccurrences() == null) {
            return null;
        }
        for (Occurrence occ : evidence.getOccurrences()) {
            String location = occ.getLocation();
            if (location != null && location.endsWith("/")) {
                return location;
            }
        }
        return null;
    }

    private static Map<String, Component> indexByPurl(List<Component> components) {
        if (components == null || components.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, Component> index = new HashMap<>(components.size());
        for (Component comp : components) {
            if (comp.getPurl() != null) {
                index.put(normalizeMavenPurl(comp.getPurl()), comp);
            }
        }
        return index;
    }

    /**
     * Normalizes a component's PURL and bom-ref in place by stripping
     * the redundant {@code ?type=jar} qualifier (jar is the PURL-spec
     * default for Maven). Recurses into sub-components.
     */
    private static void normalizePurls(Component comp) {
        String purl = comp.getPurl();
        if (purl != null) {
            String normalized = normalizeMavenPurl(purl);
            if (normalized != purl) {
                comp.setPurl(normalized);
                if (purl.equals(comp.getBomRef())) {
                    comp.setBomRef(normalized);
                }
            }
        }
        if (comp.getComponents() != null) {
            for (Component child : comp.getComponents()) {
                normalizePurls(child);
            }
        }
    }

    /**
     * Strips the redundant {@code type=jar} qualifier from a Maven PURL
     * since {@code jar} is the default type per the PURL spec. Handles
     * the qualifier in any position ({@code ?type=jar}, {@code ?type=jar&…},
     * or {@code …&type=jar}). Non-Maven PURLs and PURLs with a non-jar
     * type are returned unchanged.
     */
    static String normalizeMavenPurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:maven/")) {
            return purl;
        }
        // ?type=jar as first (or only) qualifier
        int idx = purl.indexOf("?type=jar");
        if (idx >= 0) {
            int end = idx + "?type=jar".length();
            if (end == purl.length()) {
                return purl.substring(0, idx);
            }
            if (purl.charAt(end) == '&') {
                return purl.substring(0, idx) + '?' + purl.substring(end + 1);
            }
        }
        // &type=jar as non-first qualifier
        idx = purl.indexOf("&type=jar");
        if (idx >= 0) {
            int end = idx + "&type=jar".length();
            if (end == purl.length()) {
                return purl.substring(0, idx);
            }
            if (purl.charAt(end) == '&') {
                return purl.substring(0, idx) + purl.substring(end);
            }
        }
        return purl;
    }

    private static void mergeComponentData(Component target, Component source) {
        mergeHashes(target, source);
        if (target.getLicenses() == null && source.getLicenses() != null) {
            target.setLicenses(source.getLicenses());
        }
        if (source.getComponents() != null) {
            Set<String> existingPurls = new HashSet<>();
            if (target.getComponents() != null) {
                for (Component c : target.getComponents()) {
                    if (c.getPurl() != null) {
                        existingPurls.add(normalizeMavenPurl(c.getPurl()));
                    }
                }
            }
            for (Component nested : source.getComponents()) {
                String np = normalizeMavenPurl(nested.getPurl());
                if (np == null || existingPurls.add(np)) {
                    target.addComponent(nested);
                }
            }
        }
    }

    private static void mergeHashes(Component target, Component source) {
        if (source.getHashes() == null || source.getHashes().isEmpty()) {
            return;
        }
        Set<String> existingAlgorithms = new HashSet<>();
        if (target.getHashes() != null) {
            for (Hash h : target.getHashes()) {
                existingAlgorithms.add(h.getAlgorithm());
            }
        }
        for (Hash h : source.getHashes()) {
            if (existingAlgorithms.add(h.getAlgorithm())) {
                target.addHash(h);
            }
        }
    }

    /**
     * Moves occurrence evidence from a top-level component to a nested
     * component. When {@code pathPrefix} is non-null, only occurrences
     * whose location starts with that prefix are moved (e.g. occurrences
     * under an unpacked WAR directory). When {@code pathPrefix} is
     * {@code null}, all occurrences are moved.
     *
     * @param topLevel the top-level component to remove occurrences from
     * @param nested the nested component to add occurrences to
     * @param pathPrefix the path prefix filter, or {@code null} to move all
     */
    private static void migrateOccurrences(Component topLevel, Component nested,
            String pathPrefix) {
        Evidence topEvidence = topLevel.getEvidence();
        if (topEvidence == null) {
            return;
        }
        List<Occurrence> occurrences = topEvidence.getOccurrences();
        if (occurrences == null || occurrences.isEmpty()) {
            return;
        }
        Iterator<Occurrence> it = occurrences.iterator();
        while (it.hasNext()) {
            Occurrence occ = it.next();
            if (occ.getLocation() != null
                    && (pathPrefix == null || occ.getLocation().startsWith(pathPrefix))) {
                it.remove();
                if (nested.getEvidence() == null) {
                    nested.setEvidence(new Evidence());
                }
                nested.getEvidence().addOccurrence(occ);
            }
        }
    }

    private static boolean hasOccurrences(Component component) {
        Evidence evidence = component.getEvidence();
        return evidence != null && evidence.getOccurrences() != null
                && !evidence.getOccurrences().isEmpty();
    }

    /**
     * Imports dependency entries into the target BOM's dependency section,
     * skipping entries whose ref already exists in the target.
     */
    private static void importDependencies(Bom targetBom, List<Dependency> dependencies,
            String parentPathPrefix) {
        if (dependencies == null) {
            return;
        }
        Set<String> existingRefs = new HashSet<>();
        if (targetBom.getDependencies() != null) {
            for (Dependency d : targetBom.getDependencies()) {
                existingRefs.add(normalizeMavenPurl(d.getRef()));
            }
        }
        for (Dependency dep : dependencies) {
            Dependency normalized = normalizeDependency(dep, parentPathPrefix);
            if (existingRefs.add(normalized.getRef())) {
                targetBom.addDependency(normalized);
            }
        }
    }

    private static Dependency normalizeDependency(Dependency dep,
            String parentPathPrefix) {
        String ref = prefixFileRef(normalizeMavenPurl(dep.getRef()), parentPathPrefix);
        Dependency result = new Dependency(ref);
        if (dep.getDependencies() != null) {
            for (Dependency child : dep.getDependencies()) {
                result.addDependency(normalizeDependency(child, parentPathPrefix));
            }
        }
        return result;
    }

    private static String prefixFileRef(String ref, String parentPathPrefix) {
        if (parentPathPrefix != null && ref != null
                && ref.startsWith(FILE_BOMREF_PREFIX)) {
            return FILE_BOMREF_PREFIX + parentPathPrefix
                    + ref.substring(FILE_BOMREF_PREFIX.length());
        }
        return ref;
    }

    /**
     * Searches for a component by {@code bom-ref} in the target BOM.
     *
     * <p>
     * Checks the metadata component first, then top-level components,
     * then recursively searches nested component trees.
     * </p>
     *
     * @param bom the BOM to search
     * @param bomRef the {@code bom-ref} to match
     * @return the matching component, or {@code null} if not found
     */
    public static Component findComponentByBomRef(Bom bom, String bomRef) {
        if (bomRef == null) {
            return null;
        }
        String normalized = normalizeMavenPurl(bomRef);
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component main = bom.getMetadata().getComponent();
            if (normalized.equals(normalizeMavenPurl(main.getBomRef()))) {
                return main;
            }
        }
        return searchComponentTree(bom.getComponents(), normalized);
    }

    /**
     * Recursively searches a list of components and their children
     * for a matching {@code bom-ref}.
     */
    private static Component searchComponentTree(List<Component> components, String bomRef) {
        if (components == null) {
            return null;
        }
        for (Component comp : components) {
            if (bomRef.equals(normalizeMavenPurl(comp.getBomRef()))) {
                return comp;
            }
            Component nested = searchComponentTree(comp.getComponents(), bomRef);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }
}
