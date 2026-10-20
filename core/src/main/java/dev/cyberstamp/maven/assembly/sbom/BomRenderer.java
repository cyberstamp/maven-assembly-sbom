package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.metadata.ToolInformation;

/**
 * Renders a neutral {@link AssemblyComponents} model into a CycloneDX {@link Bom}.
 *
 * <p>
 * This renderer is the output half of the neutral SBOM component model design.
 * It consumes the model populated by either discovery front-end (hash-based
 * archive analysis or event-driven provisioning) and produces a CycloneDX BOM.
 * </p>
 *
 * <p>
 * Top-level package components are deduplicated by PURL: when multiple
 * {@link PackageComponent}s share the same {@code ref.toPurl().toString()},
 * only the first creates a component and subsequent occurrences append an
 * {@link Occurrence} to the existing component's evidence (first-wins for
 * hash/licenses/identity). Nested components are emitted per-instance without
 * deduplication.
 * </p>
 */
public class BomRenderer {

    static final Comparator<Component> COMPONENT_ORDER;
    static {
        Comparator<String> nullSafe = Comparator.nullsFirst(Comparator.naturalOrder());
        COMPONENT_ORDER = Comparator
                .comparing(Component::getGroup, nullSafe)
                .thenComparing(Component::getName, nullSafe)
                .thenComparing(Component::getVersion, nullSafe);
    }

    /**
     * Renders the given assembly component model into a CycloneDX BOM.
     *
     * @param model the assembly components to render; never {@code null}
     * @return the assembled BOM, ready for serialization
     */
    public Bom render(AssemblyComponents model) {
        AssemblyMetadata metadata = model.metadata();
        Hash.Algorithm hashAlgorithm = parseHashAlgorithm(metadata.getHashAlgorithmSpec());
        String normalizedAlg = SbomUtils.normalizeAlgorithm(hashAlgorithm.getSpec());

        RenderContext ctx = new RenderContext(hashAlgorithm, normalizedAlg, metadata);

        buildTopLevelComponents(model, ctx);
        attachNestedComponents(ctx);

        Bom bom = new Bom();
        Component mainComponent = createMainComponent(metadata);
        bom.setMetadata(createMetadata(mainComponent, metadata, ctx));
        bom.setComponents(buildSortedComponentList(ctx));
        buildDependencyTree(bom, mainComponent.getBomRef(), model, ctx);

        return bom;
    }

    /**
     * Parses a hash algorithm specification string into the CycloneDX enum.
     *
     * <p>
     * When the spec is {@code null} or blank, defaults to SHA-256.
     * </p>
     *
     * @param spec the algorithm spec string (e.g. "SHA-256"), or {@code null}
     * @return the parsed algorithm
     * @throws IllegalArgumentException if the spec does not match any known
     *         algorithm
     */
    private Hash.Algorithm parseHashAlgorithm(String spec) {
        if (spec == null || spec.isBlank()) {
            return Hash.Algorithm.SHA_256;
        }
        String trimmed = spec.trim();
        // Try exact match first
        for (Hash.Algorithm alg : Hash.Algorithm.values()) {
            if (alg.getSpec().equals(trimmed)) {
                return alg;
            }
        }
        // Try case-insensitive match
        for (Hash.Algorithm alg : Hash.Algorithm.values()) {
            if (alg.getSpec().equalsIgnoreCase(trimmed)) {
                return alg;
            }
        }
        // Try matching by enum name (convert dash to underscore, uppercase)
        String enumName = trimmed.replace("-", "_").toUpperCase();
        for (Hash.Algorithm alg : Hash.Algorithm.values()) {
            if (alg.name().equals(enumName)) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unsupported hash algorithm: '" + spec + "'");
    }

    /**
     * Builds top-level components from the model, applying occurrence merge
     * for package components with duplicate PURLs.
     */
    private void buildTopLevelComponents(AssemblyComponents model, RenderContext ctx) {
        List<Component> allComponents = new ArrayList<>();

        for (AssemblyComponent neutralComp : model.components()) {
            if (neutralComp instanceof PackageComponent pkg) {
                String purl = pkg.ref().toPurl().toString();
                Component existing = ctx.componentsById.get(purl);
                if (existing != null) {
                    // Occurrence merge: append occurrence, first-wins for licenses
                    appendOccurrence(existing, pkg.archivePath());
                    applyLicensesIfAbsent(existing, CycloneDxLicenses.toLicenseChoice(pkg.licenses()));
                } else {
                    Component comp = createPackageComponent(pkg, ctx);
                    ctx.componentsById.put(purl, comp);
                    allComponents.add(comp);
                    ctx.directChildren.add(comp.getBomRef());
                }
            } else if (neutralComp instanceof FileComponent file) {
                Component comp = createFileComponent(file, ctx);
                allComponents.add(comp);
                ctx.directChildren.add(comp.getBomRef());
            }
        }

        ctx.components.addAll(allComponents);
    }

    /**
     * Creates a CycloneDX component from a {@link PackageComponent}.
     */
    private Component createPackageComponent(PackageComponent pkg, RenderContext ctx) {
        Component comp;
        if (pkg.ref() instanceof ArtifactCoords coords) {
            comp = createMavenComponent(coords);
        } else {
            // Non-Maven package component (generic assembled jar, npm, ...).
            comp = new Component();
            comp.setType(Component.Type.LIBRARY);
            if (pkg.ref() instanceof GenericPackageRef generic) {
                comp.setName(generic.name());
                comp.setVersion(generic.version());
            } else if (pkg.ref() instanceof NpmPackageRef npm) {
                comp.setName(npm.name());
                comp.setVersion(npm.version());
            }
            String purl = pkg.ref().toPurl().toString();
            comp.setBomRef(purl);
            comp.setPurl(purl);
        }
        if (pkg.hash() != null) {
            comp.addHash(new Hash(ctx.hashAlgorithm, pkg.hash()));
        }
        comp.setEvidence(buildMavenEvidence(pkg.archivePath()));
        LicenseChoice licenses = CycloneDxLicenses.toLicenseChoice(pkg.licenses());
        applyLicensesIfAbsent(comp, licenses);

        // Store nested components for later attachment
        if (!pkg.nested().isEmpty()) {
            ctx.nestedComponentsByParent.put(comp, buildNestedComponents(pkg.nested(), ctx));
        }

        // Components whose dependencies are unknown must not be declared as empty
        // leaf entries in the dependency graph (unknown != no dependencies).
        if (!pkg.dependenciesKnown()) {
            ctx.dependenciesUnknownRefs.add(comp.getBomRef());
        }

        return comp;
    }

    /**
     * Creates a LIBRARY component for a Maven artifact.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#createMavenComponent}.
     * </p>
     */
    private Component createMavenComponent(ArtifactCoords coords) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(coords.groupId());
        comp.setName(coords.artifactId());
        comp.setVersion(coords.version());
        String purl = coords.toPurl().toString();
        comp.setBomRef(purl);
        comp.setPurl(purl);
        return comp;
    }

    /**
     * Builds evidence for a Maven artifact including an identity assertion
     * and an optional occurrence.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#buildMavenEvidence}.
     * </p>
     */
    private Evidence buildMavenEvidence(String archivePath) {
        Evidence evidence = new Evidence();
        if (archivePath != null) {
            Occurrence occ = new Occurrence();
            occ.setLocation(archivePath);
            evidence.addOccurrence(occ);
        }
        evidence.setIdentities(List.of(buildMavenIdentity()));
        return evidence;
    }

    /**
     * Creates an identity assertion for Maven manifest analysis with
     * full confidence.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#buildMavenIdentity}.
     * </p>
     */
    private Identity buildMavenIdentity() {
        Identity identity = new Identity();
        identity.setField(Identity.Field.PURL);
        identity.setConfidence(1.0);
        Method method = new Method();
        method.setConfidence(1.0);
        method.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        method.setValue("maven-pom-analysis");
        identity.setMethods(List.of(method));
        return identity;
    }

    /**
     * Appends an additional {@link Occurrence} to an already-registered
     * component.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#appendOccurrence}.
     * </p>
     */
    private void appendOccurrence(Component component, String archivePath) {
        if (archivePath == null) {
            return;
        }
        Evidence evidence = component.getEvidence();
        if (evidence == null) {
            evidence = new Evidence();
            component.setEvidence(evidence);
        }
        Occurrence occ = new Occurrence();
        occ.setLocation(archivePath);
        evidence.addOccurrence(occ);
    }

    /**
     * Sets license information on a component only if it does not already
     * have any.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#applyLicensesIfAbsent}.
     * </p>
     */
    private void applyLicensesIfAbsent(Component component, LicenseChoice licenses) {
        if (licenses != null && component.getLicenses() == null) {
            component.setLicenses(licenses);
        }
    }

    /**
     * Creates a FILE component for a non-Maven file.
     *
     * <p>
     * Ported from {@code BomBuilder#createFileComponent}, applying project
     * licenses from metadata.
     * </p>
     */
    private Component createFileComponent(FileComponent file, RenderContext ctx) {
        Component comp = new Component();
        comp.setType(Component.Type.FILE);
        String fileName = SbomUtils.extractFileName(file.archivePath());
        comp.setName(fileName);
        comp.setBomRef("file:" + file.archivePath());
        comp.setPurl(buildGenericPurl(fileName, file.hash(), ctx.normalizedAlg));
        if (file.hash() != null) {
            comp.addHash(new Hash(ctx.hashAlgorithm, file.hash()));
        }
        comp.setEvidence(buildFileEvidence(file.archivePath()));
        LicenseChoice projectLicenses = CycloneDxLicenses.toLicenseChoice(ctx.metadata.getProjectLicenses());
        if (projectLicenses != null) {
            comp.setLicenses(projectLicenses);
        }

        // Store nested components for later attachment
        if (!file.nested().isEmpty()) {
            ctx.nestedComponentsByParent.put(comp, buildNestedComponents(file.nested(), ctx));
        }

        return comp;
    }

    /**
     * Builds evidence for a non-Maven file with its archive location.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#buildFileEvidence}.
     * </p>
     */
    private Evidence buildFileEvidence(String archivePath) {
        Evidence evidence = new Evidence();
        Occurrence occ = new Occurrence();
        occ.setLocation(archivePath);
        evidence.addOccurrence(occ);
        return evidence;
    }

    /**
     * Builds a Package URL for a generic (non-Maven) file.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#buildGenericPurl}.
     * </p>
     */
    private String buildGenericPurl(String fileName, String hash, String normalizedAlg) {
        Purl.Builder builder = Purl.builder()
                .setType("generic")
                .setName(fileName);
        if (hash != null) {
            builder.addQualifier("checksum", normalizedAlg + ":" + hash);
        }
        return builder.build().toString();
    }

    /**
     * Builds nested components recursively.
     */
    private List<Component> buildNestedComponents(List<AssemblyComponent> neutral, RenderContext ctx) {
        List<Component> result = new ArrayList<>(neutral.size());
        for (AssemblyComponent neutralComp : neutral) {
            if (neutralComp instanceof PackageComponent pkg) {
                Component comp = createPackageComponent(pkg, ctx);
                result.add(comp);
                String purl = pkg.ref().toPurl().toString();
                ctx.componentsById.putIfAbsent(purl, comp);
            } else if (neutralComp instanceof FileComponent file) {
                Component comp = createFileComponent(file, ctx);
                result.add(comp);
            }
        }
        return result;
    }

    /**
     * Attaches nested components to their parent components, establishing
     * the CycloneDX containment hierarchy. Each parent's nested list is
     * sorted by group/name/version for deterministic output.
     *
     * <p>
     * Ported from {@code BomBuilder#attachNestedComponents}.
     * </p>
     */
    private void attachNestedComponents(RenderContext ctx) {
        for (Map.Entry<Component, List<Component>> entry : ctx.nestedComponentsByParent.entrySet()) {
            List<Component> nested = entry.getValue();
            nested.sort(COMPONENT_ORDER);
            entry.getKey().setComponents(nested);
        }
    }

    /**
     * Builds the complete component list sorted by group, name, version.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#buildSortedComponentList}.
     * </p>
     */
    private List<Component> buildSortedComponentList(RenderContext ctx) {
        List<Component> allComponents = new ArrayList<>(ctx.components);
        allComponents.sort(COMPONENT_ORDER);
        return allComponents;
    }

    /**
     * Creates the top-level APPLICATION component representing the
     * assembly project itself.
     *
     * <p>
     * Ported from {@code BomBuilder#createMainComponent}.
     * </p>
     */
    private Component createMainComponent(AssemblyMetadata metadata) {
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setGroup(metadata.getProjectGroupId());
        main.setName(metadata.getProjectArtifactId());
        main.setVersion(metadata.getProjectVersion());
        // A producer whose main component is not a Maven artifact (e.g. a
        // provisioned distribution) can supply a synthetic purl; otherwise a
        // Maven purl is derived from the project coordinates.
        String purl = metadata.getMainComponentPurl() != null
                ? metadata.getMainComponentPurl()
                : buildMainPurl(metadata);
        main.setBomRef(purl);
        main.setPurl(purl);
        LicenseChoice projectLicenses = CycloneDxLicenses.toLicenseChoice(
                metadata.getProjectLicenses());
        if (projectLicenses != null) {
            main.setLicenses(projectLicenses);
        }
        applyProductInfo(main, metadata.getProduct());
        return main;
    }

    /**
     * Builds the Package URL for the main assembly component.
     * When no archive type is set (e.g., directory assembly) or it is
     * {@code jar}, the {@code type} qualifier is omitted.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#buildMainPurl}.
     * </p>
     */
    private String buildMainPurl(AssemblyMetadata metadata) {
        Purl.Builder builder = Purl.builder()
                .setType("maven")
                .setNamespace(metadata.getProjectGroupId())
                .setName(metadata.getProjectArtifactId())
                .setVersion(metadata.getProjectVersion());
        String archiveType = metadata.getArchiveType();
        if (archiveType != null && !archiveType.isEmpty() && !"jar".equals(archiveType)) {
            builder.addQualifier("type", archiveType);
        }
        String classifier = metadata.getClassifier();
        if (classifier != null && !classifier.isEmpty()) {
            builder.addQualifier("classifier", classifier);
        }
        return builder.build().toString();
    }

    /**
     * Applies user-configurable {@link ProductInfo} fields to the
     * main component, if set.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#applyProductInfo}.
     * </p>
     */
    private void applyProductInfo(Component main, ProductInfo product) {
        if (product == null) {
            return;
        }
        if (product.getCpe() != null) {
            main.setCpe(product.getCpe());
        }
        if (product.getDescription() != null) {
            main.setDescription(product.getDescription());
        }
        if (product.getPublisher() != null) {
            main.setPublisher(product.getPublisher());
        }
        if (product.getCopyright() != null) {
            main.setCopyright(product.getCopyright());
        }
        if (product.getSupplier() != null) {
            OrganizationalEntity supplier = product.getSupplier().toModel();
            if (supplier != null) {
                main.setSupplier(supplier);
            }
        }
        if (product.getManufacturer() != null) {
            OrganizationalEntity manufacturer = product.getManufacturer().toModel();
            if (manufacturer != null) {
                main.setManufacturer(manufacturer);
            }
        }
    }

    /**
     * Creates the BOM metadata with timestamp, main component, and tool identity.
     *
     * <p>
     * Ported from {@code BomBuilder#createMetadata}.
     * </p>
     */
    private Metadata createMetadata(Component mainComponent, AssemblyMetadata metadata, RenderContext ctx) {
        Metadata meta = new Metadata();
        Date timestamp = metadata.getTimestamp();
        meta.setTimestamp(timestamp != null ? timestamp : new Date());
        meta.setComponent(mainComponent);
        meta.setToolChoice(createToolInfo(metadata, ctx));
        return meta;
    }

    /**
     * Creates the tool identity for the BOM metadata.
     *
     * <p>
     * Ported from {@code BomBuilder#createToolInfo}, with fallback to
     * {@link ToolInfo} constants when metadata tool fields are null
     * (design decision #3: tool-coord byte-identity).
     * </p>
     */
    private ToolInformation createToolInfo(AssemblyMetadata metadata, RenderContext ctx) {
        Component tool = new Component();
        tool.setType(Component.Type.APPLICATION);

        String groupId = metadata.getToolGroupId();
        if (groupId == null) {
            groupId = ToolInfo.GROUP_ID;
        }
        tool.setGroup(groupId);

        String artifactId = metadata.getToolArtifactId();
        if (artifactId == null) {
            artifactId = ToolInfo.ARTIFACT_ID;
        }
        tool.setName(artifactId);

        String version = metadata.getToolVersion();
        if (version == null) {
            version = ToolInfo.VERSION;
        }
        tool.setVersion(version);

        ArtifactCoords toolCoords = ArtifactCoords.of(groupId, artifactId, version);
        tool.setPurl(toolCoords.toPurl().toString());

        LicenseChoice toolLicenses = CycloneDxLicenses.toLicenseChoice(
                metadata.getToolLicenses());
        if (toolLicenses != null) {
            tool.setLicenses(toolLicenses);
        }

        String toolHash = metadata.getToolHash();
        if (toolHash != null) {
            tool.addHash(new Hash(ctx.hashAlgorithm, toolHash));
        }

        ToolInformation info = new ToolInformation();
        info.setComponents(List.of(tool));
        return info;
    }

    /**
     * Populates the BOM's dependency section from the registered
     * dependency graph and explicit dependencies.
     *
     * <p>
     * Ported from {@code BomBuilder#buildDependencyTree}.
     * </p>
     */
    private void buildDependencyTree(Bom bom, String mainBomRef, AssemblyComponents model, RenderContext ctx) {
        Dependency mainDep = buildMainDependency(mainBomRef, model, ctx);
        bom.addDependency(mainDep);
        addInterArtifactDependencies(bom, model, ctx);
        addFileDependencyEntries(bom, ctx);
        addLeafEntriesForMissingRefs(bom, ctx);
        bom.getDependencies().sort(Comparator.comparing(Dependency::getRef));
    }

    /**
     * Creates the dependency entry for the main component, listing only
     * direct (non-transitive) children.
     *
     * <p>
     * Ported from {@code BomBuilder#buildMainDependency}.
     * </p>
     */
    private Dependency buildMainDependency(String mainBomRef, AssemblyComponents model, RenderContext ctx) {
        Set<String> transitiveChildren = collectTransitiveChildren(model, ctx);
        Dependency mainDep = new Dependency(mainBomRef);
        ctx.directChildren.stream()
                .filter(ref -> !transitiveChildren.contains(ref))
                .sorted()
                .forEach(ref -> mainDep.addDependency(new Dependency(ref)));
        return mainDep;
    }

    /**
     * Collects all bom-refs that appear as a child in any dependency edge.
     */
    private Set<String> collectTransitiveChildren(AssemblyComponents model, RenderContext ctx) {
        Set<String> transitiveChildren = new HashSet<>();
        for (DependencyEdge edge : model.dependencyEdges()) {
            String childPurl = edge.child().toPurl().toString();
            Component child = ctx.componentsById.get(childPurl);
            if (child != null) {
                transitiveChildren.add(child.getBomRef());
            }
        }
        return transitiveChildren;
    }

    /**
     * Adds inter-artifact dependency entries to the BOM, excluding
     * inferred dependencies that are already nested components of their parent.
     * Explicit dependencies bypass this filter (matches {@code BomBuilder}'s
     * old {@code mergeDependencyGraphs} L697-718: filters {@code artifactDependencyGraph}
     * but not {@code explicitDeps}).
     */
    private void addInterArtifactDependencies(Bom bom, AssemblyComponents model, RenderContext ctx) {
        // Build nested-refs lookup: for each parent purl, collect purls of its nested PackageComponents
        Map<String, Set<String>> nestedRefsByParent = buildNestedRefsLookup(model);

        Map<String, Set<String>> depMap = new HashMap<>();
        for (DependencyEdge edge : model.dependencyEdges()) {
            String parentPurl = edge.parent().toPurl().toString();
            String childPurl = edge.child().toPurl().toString();

            // Filter out INFERRED edges where child is nested under parent (BomBuilder L703-709)
            // Explicit edges bypass this filter to preserve manually-declared dependencies
            if (!edge.explicit()) {
                Set<String> nested = nestedRefsByParent.getOrDefault(parentPurl, Set.of());
                if (nested.contains(childPurl)) {
                    continue; // skip: containment is expressed via nesting, not dependency edges
                }
            }

            depMap.computeIfAbsent(parentPurl, k -> new HashSet<>()).add(childPurl);
        }

        for (Map.Entry<String, Set<String>> entry : depMap.entrySet()) {
            Component parent = ctx.componentsById.get(entry.getKey());
            if (parent == null) {
                continue;
            }
            Dependency dep = new Dependency(parent.getBomRef());
            resolveChildPurls(entry.getValue(), ctx).forEach(childRef -> dep.addDependency(new Dependency(childRef)));
            bom.addDependency(dep);
        }
    }

    /**
     * Builds a map of nested package refs for each parent component,
     * used to filter dependency edges whose child is already nested
     * (replicates BomBuilder's nestedIdsByParent role).
     *
     * <p>
     * {@link #collectNestedRefs} recurses through the component tree so that
     * every parent at any depth gets its own entry, but each entry's set holds
     * only that parent's <em>direct</em> nested {@code PackageComponent} refs
     * (grandchildren appear under their own immediate parent, not here). This
     * mirrors {@code BomBuilder}'s direct-only {@code nestedIdsByParent}.
     * </p>
     */
    private Map<String, Set<String>> buildNestedRefsLookup(AssemblyComponents model) {
        Map<String, Set<String>> lookup = new HashMap<>();
        for (AssemblyComponent comp : model.components()) {
            collectNestedRefs(comp, lookup);
        }
        return lookup;
    }

    /**
     * Recursively collects nested PackageComponent refs under a parent.
     */
    private void collectNestedRefs(AssemblyComponent comp, Map<String, Set<String>> lookup) {
        if (comp instanceof PackageComponent pkg) {
            String parentPurl = pkg.ref().toPurl().toString();
            Set<String> nestedRefs = new HashSet<>();
            for (AssemblyComponent nested : pkg.nested()) {
                if (nested instanceof PackageComponent nestedPkg) {
                    nestedRefs.add(nestedPkg.ref().toPurl().toString());
                }
                collectNestedRefs(nested, lookup); // recurse for deeply nested
            }
            if (!nestedRefs.isEmpty()) {
                lookup.put(parentPurl, nestedRefs);
            }
        } else if (comp instanceof FileComponent file) {
            // FileComponents can also have nested PackageComponents (e.g. shaded JARs)
            for (AssemblyComponent nested : file.nested()) {
                collectNestedRefs(nested, lookup);
            }
        }
    }

    /**
     * Resolves purl strings to bom-refs, filtering out unknown packages,
     * returning sorted results.
     *
     * <p>
     * Ported from {@code BomBuilder#resolveChildRefs}.
     * </p>
     */
    private List<String> resolveChildPurls(Set<String> childPurls, RenderContext ctx) {
        List<String> bomRefs = new ArrayList<>(childPurls.size());
        for (String childPurl : childPurls) {
            Component child = ctx.componentsById.get(childPurl);
            if (child != null) {
                bomRefs.add(child.getBomRef());
            }
        }
        bomRefs.sort(Comparator.naturalOrder());
        return bomRefs;
    }

    /**
     * Adds empty (leaf-node) dependency entries for all FILE components.
     *
     * <p>
     * Ported verbatim from {@code BomBuilder#addFileDependencyEntries}.
     * </p>
     */
    private void addFileDependencyEntries(Bom bom, RenderContext ctx) {
        for (Component comp : ctx.components) {
            if (comp.getType() == Component.Type.FILE) {
                bom.addDependency(new Dependency(comp.getBomRef()));
            }
        }
    }

    /**
     * Adds empty (leaf-node) dependency entries for any registered
     * component whose bom-ref does not yet appear in the dependency
     * graph. This ensures components discovered outside the Maven
     * dependency tree (e.g. shaded artifacts found via pom.properties)
     * still have a dependency entry per the CycloneDX spec.
     *
     * <p>
     * Ported from {@code BomBuilder#addLeafEntriesForMissingRefs}.
     * </p>
     */
    private void addLeafEntriesForMissingRefs(Bom bom, RenderContext ctx) {
        List<Dependency> dependencies = bom.getDependencies();
        Set<String> existingRefs = new HashSet<>(dependencies.size());
        for (Dependency d : dependencies) {
            existingRefs.add(d.getRef());
        }
        for (Component comp : ctx.componentsById.values()) {
            // Skip components whose dependencies are unknown: declaring an empty
            // leaf entry would misreport "unknown" as "no dependencies".
            if (ctx.dependenciesUnknownRefs.contains(comp.getBomRef())) {
                continue;
            }
            if (existingRefs.add(comp.getBomRef())) {
                bom.addDependency(new Dependency(comp.getBomRef()));
            }
        }
    }

    /**
     * Rendering context holding intermediate state and lookup maps.
     */
    private static class RenderContext {
        final Hash.Algorithm hashAlgorithm;
        final String normalizedAlg;
        final AssemblyMetadata metadata;

        final List<Component> components = new ArrayList<>();
        // Keyed by purl string to match occurrence-merge deduplication key
        final Map<String, Component> componentsById = new HashMap<>();
        // Bom-refs of components whose dependencies are unknown; excluded from leaf entries.
        final Set<String> dependenciesUnknownRefs = new HashSet<>();
        final Map<Component, List<Component>> nestedComponentsByParent = new HashMap<>();
        final Set<String> directChildren = new HashSet<>();

        RenderContext(Hash.Algorithm hashAlgorithm, String normalizedAlg, AssemblyMetadata metadata) {
            this.hashAlgorithm = hashAlgorithm;
            this.normalizedAlg = normalizedAlg;
            this.metadata = metadata;
        }
    }
}
