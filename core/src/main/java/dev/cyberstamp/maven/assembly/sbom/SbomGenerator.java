package dev.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reusable SBOM generation pipeline that analyzes file entries,
 * identifies Maven artifacts, builds a CycloneDX BOM, and merges
 * detected and external SBOMs.
 *
 * <p>
 * Used by both the {@code SbomContainerDescriptorHandler} (assembly plugin)
 * and the {@code generate} Maven goal (standalone directory scan).
 * </p>
 */
public class SbomGenerator {

    private static final Logger log = LoggerFactory.getLogger(SbomGenerator.class);

    private final MavenProject project;
    private final MavenSession session;
    private final RepositorySystem repoSystem;
    private final EffectiveModelResolver effectiveModelResolver;
    private final MessageDigest messageDigest;
    private final Hash.Algorithm bomHashAlgorithm;
    private final boolean failOnDuplicateHash;
    private final boolean failOnMissingLicense;
    private final String embeddedSboms;
    private final boolean librariesOnly;
    private final Version schemaVersion;

    private ProductInfo product;
    private LicenseEnrichment licenseEnrichment;
    private List<org.eclipse.aether.graph.Dependency> cachedManagedDeps;
    private ArchiveAnalyzer lastAnalyzer;

    SbomGenerator(MavenProject project, MavenSession session,
            RepositorySystem repoSystem,
            EffectiveModelResolver effectiveModelResolver,
            MessageDigest messageDigest, Hash.Algorithm bomHashAlgorithm,
            boolean failOnDuplicateHash, boolean failOnMissingLicense,
            String embeddedSboms, boolean librariesOnly, String schemaVersion) {
        this.project = project;
        this.session = session;
        this.repoSystem = repoSystem;
        this.effectiveModelResolver = effectiveModelResolver;
        this.messageDigest = messageDigest;
        this.bomHashAlgorithm = bomHashAlgorithm;
        this.failOnDuplicateHash = failOnDuplicateHash;
        this.failOnMissingLicense = failOnMissingLicense;
        this.embeddedSboms = embeddedSboms;
        this.librariesOnly = librariesOnly;
        this.schemaVersion = SchemaVersions.resolve(schemaVersion);
    }

    /**
     * Returns the resolved CycloneDX schema version.
     */
    Version getSchemaVersion() {
        return schemaVersion;
    }

    /**
     * Sets user-configurable metadata for the main BOM component.
     */
    void setProduct(ProductInfo product) {
        this.product = product;
    }

    /**
     * Analyzes file entries, builds a CycloneDX BOM, and merges
     * detected and external SBOMs.
     *
     * @param entries the file entries to analyze
     * @param baseDirPrefix prefix to strip from entry paths, or {@code null}
     * @param externalBoms external SBOMs to merge as top-level components
     * @param classifier the Maven classifier, or {@code null}
     * @param archiveType the archive type for the main component PURL, or {@code null}
     * @return the assembled BOM
     */
    Bom generate(List<FileEntry> entries, String baseDirPrefix,
            List<Bom> externalBoms, String assemblyId, String classifier,
            String archiveType) {
        effectiveModelResolver.init(
                session.getRepositorySession(),
                project.getRemoteProjectRepositories(),
                session.getProjects());
        licenseEnrichment = new LicenseEnrichment(
                new EffectiveModelLicenseSource(effectiveModelResolver), failOnMissingLicense);
        cachedManagedDeps = null;

        AssemblyComponents model = analyzeEntries(entries, baseDirPrefix, externalBoms);

        // Populate AssemblyMetadata
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId(project.getGroupId());
        metadata.setProjectArtifactId(project.getArtifactId());
        metadata.setProjectVersion(project.getVersion());
        metadata.setAssemblyId(assemblyId);
        metadata.setTimestamp(SbomUtils.parseBuildTimestamp(getTimestamp()));
        metadata.setHashAlgorithmSpec(bomHashAlgorithm.getSpec());
        metadata.setClassifier(classifier);
        metadata.setArchiveType(archiveType);
        metadata.setProjectLicenses(licenseEnrichment.resolve(
                project.getGroupId(), project.getArtifactId(), project.getVersion()));
        metadata.setProduct(product);
        populateToolMetadata(metadata);
        model.setMetadata(metadata);

        // Build the dependency graph, then enrich + render through the shared
        // pipeline. No jar locator is supplied: the analyzer already performed
        // shaded detection, so only license enrichment runs here.
        buildDependencyGraph(model);
        Bom bom = SbomPipeline.forModel(model)
                .licenseSource(new EffectiveModelLicenseSource(effectiveModelResolver))
                .failOnMissingLicense(failOnMissingLicense)
                .render();

        // Post-processing (detected/external SBOMs, filtering, dedup)
        ArchiveIndex archiveIndex = ArchiveIndex.of(entries, baseDirPrefix, bomHashAlgorithm.getSpec());
        processDiscoveredSboms(bom, model, archiveIndex);
        processExternalBoms(bom, externalBoms, archiveIndex);

        String normalizedAlg = archiveIndex.normalizedAlg();
        removeTopLevelFilesDuplicatedByNested(bom, normalizedAlg);
        replaceFileComponentsWithLibraries(bom, normalizedAlg);
        if (librariesOnly) {
            removeFileComponents(bom);
        }
        deduplicateBomRefs(bom);
        return bom;
    }

    private AssemblyComponents analyzeEntries(List<FileEntry> entries,
            String baseDirPrefix, List<Bom> externalBoms) {
        boolean detectEmbeddedSboms = !"ignore".equalsIgnoreCase(embeddedSboms);
        lastAnalyzer = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem,
                project, session, messageDigest, failOnDuplicateHash,
                externalBoms, detectEmbeddedSboms);
        return lastAnalyzer.analyze(entries, baseDirPrefix);
    }

    private void processDiscoveredSboms(Bom bom, AssemblyComponents model, ArchiveIndex archiveIndex) {
        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                embeddedSboms, archiveIndex);
        transform.apply(bom, model, owner -> resolveParentBomRef(owner, bom, model));
    }

    static Bom filterSbomByArchive(Bom sbom, ArchiveIndex archiveIndex, String parentPathPrefix) {
        if (sbom.getComponents() == null) {
            return sbom;
        }
        ArchiveIndex index = archiveIndex.scopedTo(parentPathPrefix);
        Set<String> survivingRefs = new HashSet<>();
        List<Component> filtered = new ArrayList<>();
        for (Component comp : sbom.getComponents()) {
            ComponentView cv = new ComponentView(comp, index.normalizedAlg());
            if (matchesArchive(cv, index)) {
                correctOccurrences(cv, index);
                ensureMavenManifestIdentity(comp);
                filtered.add(comp);
                collectBomRefs(comp, survivingRefs);
            } else {
                log.debug("Filtering out component {} from SBOM: no matching file in archive", comp.getPurl());
            }
        }
        Bom result = new Bom();
        result.setComponents(filtered);
        if (sbom.getDependencies() != null) {
            List<Dependency> filteredDeps = new ArrayList<>();
            for (Dependency dep : sbom.getDependencies()) {
                if (survivingRefs.contains(dep.getRef())) {
                    Dependency pruned = filterDependencyChildren(dep, survivingRefs);
                    filteredDeps.add(pruned);
                }
            }
            if (!filteredDeps.isEmpty()) {
                result.setDependencies(filteredDeps);
            }
        }
        return result;
    }

    private static Dependency filterDependencyChildren(Dependency dep, Set<String> survivingRefs) {
        if (dep.getDependencies() == null || dep.getDependencies().isEmpty()) {
            return dep;
        }
        Dependency result = new Dependency(
                dep.getRef());
        for (Dependency child : dep.getDependencies()) {
            if (survivingRefs.contains(child.getRef())) {
                result.addDependency(new Dependency(child.getRef()));
            }
        }
        return result;
    }

    private static void collectBomRefs(Component comp, Set<String> refs) {
        if (comp.getBomRef() != null) {
            refs.add(comp.getBomRef());
        }
        if (comp.getComponents() != null) {
            for (Component child : comp.getComponents()) {
                collectBomRefs(child, refs);
            }
        }
    }

    /**
     * Checks whether a component from an external/embedded SBOM corresponds
     * to a file actually present in the archive.
     */
    private static boolean matchesArchive(ComponentView cv, ArchiveIndex index) {
        if (hasMatchingOccurrence(cv, index)) {
            if (cv.component().getType() == Component.Type.FILE
                    && cv.hasVerifiableHash()
                    && !index.containsHash(cv.hash())) {
                return false;
            }
            return true;
        }
        if (hasEmptyOccurrence(cv, index)) {
            return true;
        }
        if (cv.hasOccurrences()) {
            if (isNpmComponent(cv.component())) {
                return true;
            }
            if (index.findPathByHash(cv.hash()) != null) {
                return true;
            }
            return false;
        }
        if (!cv.hasVerifiableHash()) {
            return true;
        }
        return index.containsHash(cv.hash());
    }

    private static boolean hasMatchingOccurrence(ComponentView cv, ArchiveIndex index) {
        for (String loc : cv.locations()) {
            if (!loc.isEmpty() && index.containsPath(loc)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasEmptyOccurrence(ComponentView cv, ArchiveIndex index) {
        if (!index.isScoped()
                || cv.component().getType() == Component.Type.FILE) {
            return false;
        }
        for (String loc : cv.locations()) {
            if (loc.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Adds a {@code manifest-analysis} identity to a Maven component from an
     * external/embedded SBOM that survived archive filtering (i.e. was verified
     * present in the distribution) but carries no identity of its own — for
     * example a Quarkus-generated SBOM component, which brings a rich
     * description/publisher but no evidence identity. This restores the same
     * provenance the analyzer records for components it identifies directly.
     *
     * <p>
     * Only Maven components are affected; components already carrying an
     * identity, and non-Maven (e.g. npm) components, are left untouched.
     * </p>
     */
    private static void ensureMavenManifestIdentity(Component comp) {
        String purl = comp.getPurl();
        if (purl == null || !purl.startsWith("pkg:maven/")) {
            return;
        }
        Evidence evidence = comp.getEvidence();
        if (evidence != null && evidence.getIdentities() != null
                && !evidence.getIdentities().isEmpty()) {
            return;
        }
        if (evidence == null) {
            evidence = new Evidence();
            comp.setEvidence(evidence);
        }
        Identity identity = new Identity();
        identity.setField(Identity.Field.PURL);
        identity.setConfidence(1.0);
        Method method = new Method();
        method.setConfidence(1.0);
        method.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        method.setValue("maven-pom-analysis");
        identity.setMethods(List.of(method));
        evidence.setIdentities(List.of(identity));
    }

    /**
     * Corrects occurrence paths on a component that survived archive
     * filtering. If occurrences already match, this is a no-op.
     */
    private static void correctOccurrences(ComponentView cv, ArchiveIndex index) {
        if (hasMatchingOccurrence(cv, index)) {
            return;
        }
        String location = index.findPathByHash(cv.hash());
        if (location == null) {
            return;
        }
        Evidence evidence = cv.component().getEvidence();
        if (evidence == null) {
            evidence = new Evidence();
            cv.component().setEvidence(evidence);
        }
        List<Occurrence> occurrences = new ArrayList<>(1);
        Occurrence occ = new Occurrence();
        occ.setLocation(location);
        occurrences.add(occ);
        evidence.setOccurrences(occurrences);
    }

    private static boolean isNpmComponent(Component comp) {
        String purl = comp.getPurl();
        return purl != null && purl.startsWith("pkg:npm/");
    }

    private void processExternalBoms(Bom bom, List<Bom> externalBomList, ArchiveIndex archiveIndex) {
        if (externalBomList.isEmpty()) {
            return;
        }
        for (Bom externalBom : externalBomList) {
            Bom filtered = filterSbomByArchive(externalBom, archiveIndex, null);
            BomMerger.mergeFlat(bom, filtered);
        }
    }

    static void removeTopLevelFilesDuplicatedByNested(Bom bom, String normalizedAlg) {
        if (bom.getComponents() == null) {
            return;
        }
        ComponentList comps = ComponentList.of(bom);
        if (comps.isEmpty()) {
            return;
        }
        Set<String> nestedFileHashes = new HashSet<>();
        Set<String> nestedFileBomRefs = new HashSet<>();
        for (Component comp : comps) {
            collectNestedFileHashes(comp, normalizedAlg, nestedFileHashes);
            collectNestedFileBomRefs(comp, nestedFileBomRefs);
        }
        if (nestedFileHashes.isEmpty()) {
            return;
        }
        Set<String> removedRefs = new HashSet<>();
        comps.removeIf(comp -> {
            if (comp.getType() != Component.Type.FILE) {
                return false;
            }
            String hash = SbomUtils.extractHash(comp, normalizedAlg);
            if (hash != null && nestedFileHashes.contains(hash)) {
                if (comp.getBomRef() != null) {
                    removedRefs.add(comp.getBomRef());
                }
                return true;
            }
            return false;
        });
        if (!removedRefs.isEmpty()) {
            DependencyList deps = DependencyList.of(bom);
            deps.removeIf(d -> removedRefs.contains(d.getRef())
                    && !nestedFileBomRefs.contains(d.getRef()));
            for (Dependency dep : deps) {
                DependencyList.ofChildren(dep).removeIf(
                        child -> removedRefs.contains(child.getRef())
                                && !nestedFileBomRefs.contains(child.getRef()));
            }
        }
    }

    private static void collectNestedFileBomRefs(Component parent, Set<String> bomRefs) {
        if (parent.getComponents() == null) {
            return;
        }
        for (Component child : parent.getComponents()) {
            if (child.getType() == Component.Type.FILE && child.getBomRef() != null) {
                bomRefs.add(child.getBomRef());
            }
            collectNestedFileBomRefs(child, bomRefs);
        }
    }

    private static void collectNestedFileHashes(Component parent, String normalizedAlg, Set<String> hashes) {
        if (parent.getComponents() == null) {
            return;
        }
        for (Component child : parent.getComponents()) {
            if (child.getType() == Component.Type.FILE) {
                String hash = SbomUtils.extractHash(child, normalizedAlg);
                if (hash != null) {
                    hashes.add(hash);
                }
            }
            collectNestedFileHashes(child, normalizedAlg, hashes);
        }
    }

    static void replaceFileComponentsWithLibraries(Bom bom, String normalizedAlg) {
        if (bom.getComponents() == null) {
            return;
        }
        ComponentList comps = ComponentList.of(bom);
        if (comps.isEmpty()) {
            return;
        }
        Map<String, List<Component>> filesByHash = new HashMap<>();
        for (Component comp : comps) {
            if (comp.getBomRef() != null
                    && comp.getBomRef().startsWith("file:")) {
                String hash = SbomUtils.extractHash(comp, normalizedAlg);
                if (hash != null) {
                    filesByHash.computeIfAbsent(hash,
                            k -> new ArrayList<>()).add(comp);
                }
            }
        }
        if (filesByHash.isEmpty()) {
            return;
        }
        Map<String, String> fileToLibRef = new HashMap<>();
        for (Component comp : comps) {
            matchFilesByLibraryHash(comp, filesByHash, normalizedAlg, fileToLibRef);
        }
        if (fileToLibRef.isEmpty()) {
            return;
        }
        comps.removeIf(c -> fileToLibRef.containsKey(c.getBomRef()));
        DependencyList deps = DependencyList.of(bom);
        List<Dependency> toRemove = new ArrayList<>();
        for (Dependency dep : deps) {
            String replacement = fileToLibRef.get(dep.getRef());
            if (replacement != null) {
                toRemove.add(dep);
            } else {
                replaceDependsOnRefs(dep, fileToLibRef);
            }
        }
        for (Dependency dep : toRemove) {
            deps.remove(dep);
        }
    }

    private static void matchFilesByLibraryHash(Component comp,
            Map<String, List<Component>> filesByHash,
            String normalizedAlg, Map<String, String> fileToLibRef) {
        if (comp.getType() == Component.Type.LIBRARY) {
            String hash = SbomUtils.extractHash(comp, normalizedAlg);
            if (hash != null) {
                List<Component> fileComps = filesByHash.get(hash);
                if (fileComps != null) {
                    for (Component fileComp : fileComps) {
                        fileToLibRef.putIfAbsent(fileComp.getBomRef(), comp.getBomRef());
                    }
                }
            }
        }
        if (comp.getComponents() != null) {
            for (Component nested : comp.getComponents()) {
                matchFilesByLibraryHash(nested, filesByHash,
                        normalizedAlg, fileToLibRef);
            }
        }
    }

    private static void replaceDependsOnRefs(
            Dependency dep,
            Map<String, String> refMap) {
        DependencyList children = DependencyList.ofChildren(dep);
        if (children.isEmpty()) {
            return;
        }
        List<Dependency> toAdd = new ArrayList<>();
        List<Dependency> toRemove = new ArrayList<>();
        for (Dependency child : children) {
            String replacement = refMap.get(child.getRef());
            if (replacement != null) {
                toRemove.add(child);
                if (!children.containsRef(replacement)) {
                    toAdd.add(new Dependency(replacement));
                }
            }
            replaceDependsOnRefs(child, refMap);
        }
        for (Dependency r : toRemove) {
            children.remove(r);
        }
        for (Dependency a : toAdd) {
            children.add(a);
        }
    }

    /**
     * Removes all {@link Component.Type#FILE FILE} components from the BOM
     * (top-level, main component sub-components, and nested) and cleans up
     * any dependency references that point to removed components. The main
     * component itself is never removed, even if its type is FILE.
     *
     * @param bom the BOM to modify in place
     */
    static void removeFileComponents(Bom bom) {
        Set<String> removedRefs = new HashSet<>();
        bom.setComponents(filterOutFileComponents(bom.getComponents(), removedRefs));
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            bom.getMetadata().getComponent().setComponents(
                    filterOutFileComponents(bom.getMetadata().getComponent().getComponents(), removedRefs));
        }
        if (!removedRefs.isEmpty()) {
            DependencyList deps = DependencyList.of(bom);
            deps.removeIf(d -> removedRefs.contains(d.getRef()));
            for (Dependency dep : deps) {
                removeFileRefs(dep, removedRefs);
            }
        }
    }

    private static List<Component> filterOutFileComponents(List<Component> components,
            Set<String> removedRefs) {
        if (components == null) {
            return null;
        }
        List<Component> result = new ArrayList<>();
        for (Component comp : components) {
            if (comp.getType() == Component.Type.FILE) {
                if (comp.getBomRef() != null) {
                    removedRefs.add(comp.getBomRef());
                }
            } else {
                comp.setComponents(filterOutFileComponents(comp.getComponents(), removedRefs));
                result.add(comp);
            }
        }
        return result;
    }

    /**
     * Recursively removes child dependency references whose ref is contained
     * in {@code removedRefs}.
     *
     * @param dep the dependency whose children are filtered
     * @param removedRefs the set of bomRefs to remove
     */
    private static void removeFileRefs(Dependency dep, Set<String> removedRefs) {
        DependencyList children = DependencyList.ofChildren(dep);
        if (children.isEmpty()) {
            return;
        }
        children.removeByRefs(removedRefs);
        for (Dependency child : children) {
            removeFileRefs(child, removedRefs);
        }
    }

    static void deduplicateBomRefs(Bom bom) {
        Map<String, Component> seen = new HashMap<>();
        Map<String, String> renames = new HashMap<>();
        if (bom.getComponents() != null) {
            deduplicateBomRefs(bom.getComponents(), seen, renames);
        }
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null
                && bom.getMetadata().getComponent().getComponents() != null) {
            deduplicateBomRefs(
                    bom.getMetadata().getComponent().getComponents(), seen, renames);
        }
        if (!renames.isEmpty() && bom.getDependencies() != null) {
            Map<String, List<String>> originalToNew = new HashMap<>();
            for (Map.Entry<String, String> e : renames.entrySet()) {
                originalToNew.computeIfAbsent(e.getValue(),
                        k -> new ArrayList<>()).add(e.getKey());
            }
            List<Dependency> toAdd = new ArrayList<>();
            for (Dependency dep : bom.getDependencies()) {
                List<String> newRefs = originalToNew.get(dep.getRef());
                if (newRefs != null) {
                    for (String newRef : newRefs) {
                        Dependency clone = new Dependency(newRef);
                        if (dep.getDependencies() != null) {
                            for (Dependency child : dep.getDependencies()) {
                                clone.addDependency(
                                        new Dependency(
                                                child.getRef()));
                            }
                        }
                        toAdd.add(clone);
                    }
                }
                addRenamedDependsOnRefs(dep, originalToNew);
            }
            bom.getDependencies().addAll(toAdd);
        }
    }

    private static void deduplicateBomRefs(
            List<Component> components,
            Map<String, Component> seen,
            Map<String, String> renames) {
        for (Component comp : components) {
            String ref = comp.getBomRef();
            if (ref != null && seen.putIfAbsent(ref, comp) != null) {
                int suffix = 2;
                String unique = ref + "#" + suffix;
                while (seen.containsKey(unique)) {
                    unique = ref + "#" + ++suffix;
                }
                renames.put(unique, ref);
                comp.setBomRef(unique);
                seen.put(unique, comp);
            }
        }
        for (Component comp : components) {
            if (comp.getComponents() != null) {
                deduplicateBomRefs(comp.getComponents(), seen, renames);
            }
        }
    }

    private static void addRenamedDependsOnRefs(
            Dependency dep, Map<String, List<String>> originalToNew) {
        if (dep.getDependencies() == null) {
            return;
        }
        List<Dependency> childrenToAdd = new ArrayList<>();
        for (Dependency child : dep.getDependencies()) {
            List<String> newRefs = originalToNew.get(child.getRef());
            if (newRefs != null) {
                for (String newRef : newRefs) {
                    childrenToAdd.add(new Dependency(newRef));
                }
            }
        }
        for (Dependency d : childrenToAdd) {
            dep.addDependency(d);
        }
    }

    /**
     * Resolves the bom-ref for a discovered SBOM's parent artifact.
     *
     * <p>
     * Returns {@code coords.toPurl().toString()} if {@code coords} is a known
     * model component (a top-level or nested {@link PackageComponent} ref),
     * else falls back to the main component bomRef.
     * </p>
     */
    private String resolveParentBomRef(PackageRef parentRef,
            Bom bom, AssemblyComponents model) {
        if (parentRef != null) {
            String purl = parentRef.toPurl().toString();
            // Check if this purl exists in the model
            if (isKnownPackageRef(parentRef, model)) {
                return purl;
            }
        }
        return bom.getMetadata().getComponent().getBomRef();
    }

    /**
     * Checks if a {@link PackageRef} is present in the model as a
     * {@link PackageComponent}.
     */
    private boolean isKnownPackageRef(PackageRef ref, AssemblyComponents model) {
        for (AssemblyComponent comp : model.components()) {
            if (containsPackageRef(comp, ref)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Recursively searches for a {@link PackageRef} in a component tree.
     */
    private boolean containsPackageRef(AssemblyComponent comp,
            PackageRef ref) {
        if (comp instanceof PackageComponent pkg) {
            if (pkg.ref().toPurl().toString().equals(ref.toPurl().toString())) {
                return true;
            }
            for (AssemblyComponent nested : pkg.nested()) {
                if (containsPackageRef(nested, ref)) {
                    return true;
                }
            }
        } else if (comp instanceof FileComponent file) {
            for (AssemblyComponent nested : file.nested()) {
                if (containsPackageRef(nested, ref)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Parses external SBOM files from a comma-separated path string,
     * resolving relative paths against the given base directory.
     *
     * @param externalSboms comma-separated SBOM file paths, or {@code null}
     * @param baseDir the base directory for relative path resolution, or {@code null}
     * @return the parsed BOMs (never {@code null})
     */
    public static List<Bom> parseExternalBoms(String externalSboms, Path baseDir) {
        if (externalSboms == null || externalSboms.isBlank()) {
            return List.of();
        }
        List<Bom> result = new ArrayList<>();
        for (String pathStr : externalSboms.split(",")) {
            pathStr = pathStr.trim();
            if (pathStr.isEmpty()) {
                continue;
            }
            Path bomPath = Path.of(pathStr);
            if (!bomPath.isAbsolute() && baseDir != null) {
                bomPath = baseDir.resolve(pathStr);
            }
            if (!Files.isRegularFile(bomPath)) {
                log.warn("External SBOM file not found: {}", bomPath);
                continue;
            }
            Bom bom = BomReader.readBom(bomPath.toFile());
            if (bom != null) {
                log.debug("Loaded external SBOM from {} ({} components)", bomPath,
                        bom.getComponents() != null ? bom.getComponents().size() : 0);
                result.add(bom);
            }
        }
        return result;
    }

    private String getTimestamp() {
        return project.getProperties() != null
                ? project.getProperties().getProperty("project.build.outputTimestamp")
                : null;
    }

    private void populateToolMetadata(AssemblyMetadata metadata) {
        metadata.setToolGroupId(ToolInfo.GROUP_ID);
        metadata.setToolArtifactId(ToolInfo.ARTIFACT_ID);
        metadata.setToolVersion(ToolInfo.VERSION);
        try {
            metadata.setToolLicenses(licenseEnrichment.resolve(
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION));
        } catch (Exception e) {
            log.debug("Could not resolve tool licenses for {}:{}:{}",
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION, e);
        }
        resolveToolHash(metadata);
    }

    private void resolveToolHash(AssemblyMetadata metadata) {
        try {
            DefaultArtifact toolArtifact = new DefaultArtifact(
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, "jar", ToolInfo.VERSION);
            ArtifactRequest request = new ArtifactRequest(
                    toolArtifact, project.getRemoteProjectRepositories(), null);
            ArtifactResult result = repoSystem.resolveArtifact(
                    session.getRepositorySession(), request);
            File jarFile = result.getArtifact().getFile();
            if (jarFile != null && jarFile.isFile()) {
                metadata.setToolHash(SbomUtils.computeHash(messageDigest, jarFile.toPath()));
            }
        } catch (Exception e) {
            log.debug("Could not resolve tool artifact {}:{}:{}",
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION, e);
        }
    }

    /**
     * Builds the inferred dependency graph from Maven dependency resolution
     * and adds the edges to the model as {@link DependencyEdge}s with
     * {@code explicit=false}.
     *
     * <p>
     * Reads {@code nestedDepsByParent} from the analyzer's side-data getter
     * (Ruling C2-C: Aether confinement) and {@code knownIds} from the model.
     * Preserves the try/catch warn-and-continue behavior from the legacy
     * implementation.
     * </p>
     */
    private void buildDependencyGraph(AssemblyComponents model) {
        try {
            Map<ArtifactCoords, List<org.eclipse.aether.graph.Dependency>> nestedDepsByParent = lastAnalyzer
                    .nestedDepsByParent();
            if (nestedDepsByParent == null) {
                nestedDepsByParent = Map.of();
            }
            Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = collectDependencyEdges(nestedDepsByParent);
            Set<ArtifactCoords> knownIds = collectKnownArtifactCoords(model);
            Map<ArtifactCoords, List<ArtifactCoords>> graph = filterEdges(collectedEdges, knownIds);
            // Add inferred edges to the model with explicit=false
            for (Map.Entry<ArtifactCoords, List<ArtifactCoords>> entry : graph.entrySet()) {
                for (ArtifactCoords child : entry.getValue()) {
                    model.addDependencyEdge(new DependencyEdge(entry.getKey(), child, false));
                }
            }
        } catch (Exception e) {
            log.warn("Failed to build dependency graph,"
                    + " SBOM will omit dependency information", e);
        }
    }

    /**
     * Collects all known artifact coordinates from the model (top-level and
     * nested {@link PackageComponent}s), for use in dependency graph filtering.
     */
    private Set<ArtifactCoords> collectKnownArtifactCoords(AssemblyComponents model) {
        Set<ArtifactCoords> ids = new HashSet<>();
        for (AssemblyComponent comp : model.components()) {
            collectPackageRefs(comp, ids);
        }
        return ids;
    }

    /**
     * Recursively collects {@link ArtifactCoords} from {@link PackageComponent}s.
     */
    private void collectPackageRefs(AssemblyComponent comp,
            Set<ArtifactCoords> ids) {
        if (comp instanceof PackageComponent pkg) {
            if (pkg.ref() instanceof ArtifactCoords coords) {
                ids.add(coords);
            }
            for (AssemblyComponent nested : pkg.nested()) {
                collectPackageRefs(nested, ids);
            }
        } else if (comp instanceof FileComponent file) {
            for (AssemblyComponent nested : file.nested()) {
                collectPackageRefs(nested, ids);
            }
        }
    }

    private Map<ArtifactCoords, Set<ArtifactCoords>> collectDependencyEdges(
            Map<ArtifactCoords, List<org.eclipse.aether.graph.Dependency>> nestedDepsByParent) throws Exception {
        Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = new ConcurrentHashMap<>();

        DefaultRepositorySystemSession mutableSession = new DefaultRepositorySystemSession(session.getRepositorySession());
        mutableSession.setDependencySelector(new EdgeCollectorSelectorFactory(
                session.getRepositorySession().getDependencySelector(), collectedEdges));

        List<org.eclipse.aether.graph.Dependency> projectManagedDeps = collectManagedDependencies();
        CollectRequest request = buildCollectRequest(
                toAetherDependencies(project.getDependencies()), projectManagedDeps);
        repoSystem.collectDependencies(mutableSession, request);

        for (Map.Entry<ArtifactCoords, List<org.eclipse.aether.graph.Dependency>> entry : nestedDepsByParent.entrySet()) {
            List<org.eclipse.aether.graph.Dependency> parentManagedDeps = resolveManagedDependencies(entry.getKey());
            CollectRequest nestedRequest = buildCollectRequest(entry.getValue(), parentManagedDeps);
            repoSystem.collectDependencies(mutableSession, nestedRequest);
        }

        return collectedEdges;
    }

    private List<org.eclipse.aether.graph.Dependency> resolveManagedDependencies(ArtifactCoords coords) {
        Model model = effectiveModelResolver.resolveEffectiveModel(
                coords.groupId(), coords.artifactId(), coords.version());
        if (model == null || model.getDependencyManagement() == null
                || model.getDependencyManagement().getDependencies() == null) {
            return List.of();
        }
        return toAetherDependencies(model.getDependencyManagement().getDependencies());
    }

    private List<org.eclipse.aether.graph.Dependency> collectManagedDependencies() {
        if (cachedManagedDeps != null) {
            return cachedManagedDeps;
        }
        List<org.eclipse.aether.graph.Dependency> managedDeps;
        if (project.getDependencyManagement() != null
                && project.getDependencyManagement().getDependencies() != null) {
            managedDeps = toAetherDependencies(
                    project.getDependencyManagement().getDependencies());
        } else {
            managedDeps = List.of();
        }
        cachedManagedDeps = managedDeps;
        return managedDeps;
    }

    private List<org.eclipse.aether.graph.Dependency> toAetherDependencies(
            List<org.apache.maven.model.Dependency> deps) {
        List<org.eclipse.aether.graph.Dependency> result = new ArrayList<>(deps.size());
        for (org.apache.maven.model.Dependency dep : deps) {
            result.add(toAetherDependency(dep));
        }
        return result;
    }

    private static org.eclipse.aether.graph.Dependency toAetherDependency(org.apache.maven.model.Dependency dep) {
        return new org.eclipse.aether.graph.Dependency(
                SbomUtils.toAetherArtifact(dep.getGroupId(), dep.getArtifactId(),
                        dep.getVersion(), dep.getType(), dep.getClassifier()),
                dep.getScope());
    }

    private CollectRequest buildCollectRequest(List<org.eclipse.aether.graph.Dependency> deps,
            List<org.eclipse.aether.graph.Dependency> managedDeps) {
        CollectRequest request = new CollectRequest();
        request.setDependencies(deps);
        request.setManagedDependencies(managedDeps);
        request.setRepositories(project.getRemoteProjectRepositories());
        return request;
    }

    private Map<ArtifactCoords, List<ArtifactCoords>> filterEdges(
            Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges,
            Set<ArtifactCoords> knownIds) {
        Map<ArtifactCoords, List<ArtifactCoords>> graph = new HashMap<>();
        for (ArtifactCoords id : knownIds) {
            Set<ArtifactCoords> children = collectedEdges.get(id);
            if (children == null) {
                continue;
            }
            List<ArtifactCoords> filtered = new ArrayList<>(children.size());
            for (ArtifactCoords childId : children) {
                if (knownIds.contains(childId)) {
                    filtered.add(childId);
                }
            }
            graph.put(id, filtered);
        }
        return graph;
    }
}
