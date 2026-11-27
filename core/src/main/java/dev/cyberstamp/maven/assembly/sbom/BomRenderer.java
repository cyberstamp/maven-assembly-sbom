package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

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
 * hash/licenses, first non-null for identity). Nested components are emitted per-instance without
 * deduplication.
 * </p>
 *
 * <h2>Bom-refs</h2>
 * <p>
 * Every copy of a component is its own CycloneDX component with a unique
 * bom-ref. A package's bom-ref is its purl and a file's is
 * {@code file:<archivePath>}. When several copies share one, the first in
 * output order keeps it and the others get {@code #2}, {@code #3}, ...
 * appended. Output order is the sorted top-level components first, then the
 * nested components breadth-first, level by level, so a top-level copy
 * always keeps the plain purl. <strong>This is a contract:</strong> producers
 * (e.g. one merging an embedded SBOM under {@code coords.toPurl()}) rely on
 * the plain purl naming the top-level copy. {@link #renderWithRefs} reports
 * the bom-ref given to each model {@link ComponentId}.
 * </p>
 *
 * <h2>Dependencies</h2>
 * <p>
 * Dependency entries come from the model's {@link DependencyEdge}s, which
 * name copies by id, so an entry always lists the specific copies its
 * component depends on. A component whose dependencies are unknown gets no
 * entry unless an edge starts from it (an empty entry would declare that it
 * has none); the main component depends on every top-level component that no
 * edge points to.
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
        return renderWithRefs(model).bom();
    }

    /**
     * Renders the model and reports the bom-ref given to each of its
     * component copies (see "Bom-refs" in the class description).
     *
     * @param model the assembly components to render; never {@code null}
     * @return the assembled BOM and the bom-ref of every component id
     */
    RenderedBom renderWithRefs(AssemblyComponents model) {
        AssemblyMetadata metadata = model.metadata();
        Hash.Algorithm hashAlgorithm = parseHashAlgorithm(metadata.getHashAlgorithmSpec());
        String normalizedAlg = SbomUtils.normalizeAlgorithm(hashAlgorithm.getSpec());

        RenderContext ctx = new RenderContext(hashAlgorithm, normalizedAlg, metadata);

        buildTopLevelComponents(model, ctx);
        attachNestedComponents(ctx);
        List<Component> topLevel = buildSortedComponentList(ctx);
        Component mainComponent = createMainComponent(metadata);
        assignUniqueBomRefs(mainComponent, topLevel);

        Bom bom = new Bom();
        bom.setMetadata(createMetadata(mainComponent, metadata, ctx));
        bom.setComponents(topLevel);
        buildDependencyTree(bom, mainComponent.getBomRef(), model, ctx);

        return new RenderedBom(bom, collectBomRefs(ctx));
    }

    /**
     * Gives every rendered component a unique bom-ref: walking the sorted
     * top-level components first and then the nested ones breadth-first, the
     * first holder of a bom-ref keeps it and each later one gets the next free
     * {@code #n} (from 2). Nested lists are already sorted by
     * {@link #attachNestedComponents}, so the order, and thus the naming, is
     * deterministic.
     *
     * @param topLevel the sorted top-level components
     */
    private static void assignUniqueBomRefs(Component mainComponent, List<Component> topLevel) {
        Set<String> taken = new HashSet<>();
        if (mainComponent != null && mainComponent.getBomRef() != null) {
            taken.add(mainComponent.getBomRef());
        }
        List<Component> level = topLevel;
        while (!level.isEmpty()) {
            List<Component> next = null;
            for (Component comp : level) {
                String base = comp.getBomRef();
                if (base != null && !taken.add(base)) {
                    int n = 2;
                    String unique = base + '#' + n;
                    while (!taken.add(unique)) {
                        unique = base + '#' + ++n;
                    }
                    comp.setBomRef(unique);
                }
                List<Component> nested = comp.getComponents();
                if (nested != null && !nested.isEmpty()) {
                    if (next == null) {
                        next = new ArrayList<>();
                    }
                    next.addAll(nested);
                }
            }
            level = next == null ? List.of() : next;
        }
    }

    /**
     * Collects the final bom-ref of every rendered component copy.
     *
     * @return an unmodifiable map from component id to bom-ref
     */
    private static Map<ComponentId, String> collectBomRefs(RenderContext ctx) {
        Map<ComponentId, String> refs = new HashMap<>((int) (ctx.byId.size() / 0.75f) + 1);
        for (Map.Entry<ComponentId, Component> e : ctx.byId.entrySet()) {
            refs.put(e.getKey(), e.getValue().getBomRef());
        }
        return Collections.unmodifiableMap(refs);
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
        // Occurrence merge only joins top-level instances of a purl. A nested
        // copy (e.g. a dependency bundled in a shaded jar, registered while an
        // earlier top-level component was rendered) has no file of its own and
        // must not absorb a top-level component's path.
        Map<String, Component> topLevelById = new HashMap<>();

        for (AssemblyComponent neutralComp : model.components()) {
            if (neutralComp instanceof PackageComponent pkg) {
                String purl = pkg.ref().toPurl().toString();
                Component existing = topLevelById.get(purl);
                if (existing != null) {
                    // Occurrence merge: append occurrence, first-wins for licenses,
                    // first non-null for identity. The merged copy's id names
                    // the merged component, so edges to or from it resolve.
                    ctx.byId.put(pkg.id(), existing);
                    if (pkg.dependenciesKnown()) {
                        ctx.knownDependencies.add(existing);
                    }
                    appendOccurrence(existing, pkg.archivePath());
                    applyIdentityIfAbsent(existing, pkg);
                    applyLicensesIfAbsent(existing, CycloneDxLicenses.toLicenseChoice(pkg.licenses()));
                } else {
                    Component comp = createPackageComponent(pkg, ctx);
                    topLevelById.put(purl, comp);
                    allComponents.add(comp);
                }
            } else if (neutralComp instanceof FileComponent file) {
                allComponents.add(createFileComponent(file, ctx));
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
        comp.setEvidence(buildPackageEvidence(pkg));
        LicenseChoice licenses = CycloneDxLicenses.toLicenseChoice(pkg.licenses());
        applyLicensesIfAbsent(comp, licenses);

        // Store nested components for later attachment
        if (!pkg.nested().isEmpty()) {
            ctx.nestedComponentsByParent.put(comp, buildNestedComponents(pkg.nested(), ctx));
        }

        // Components whose dependencies are unknown must not be declared as empty
        // leaf entries in the dependency graph (unknown != no dependencies).
        if (pkg.dependenciesKnown()) {
            ctx.knownDependencies.add(comp);
        }
        ctx.packages.add(comp);
        ctx.byId.put(pkg.id(), comp);

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
     * Builds evidence for a package component: an optional occurrence, and an
     * identity only when the component carries an {@link Identification}.
     * Returns {@code null} when there is nothing to say, rather than an empty
     * evidence object.
     */
    private Evidence buildPackageEvidence(PackageComponent pkg) {
        Identity identity = identityOf(pkg);
        if (pkg.archivePath() == null && identity == null) {
            return null;
        }
        Evidence evidence = new Evidence();
        if (pkg.archivePath() != null) {
            Occurrence occ = new Occurrence();
            occ.setLocation(pkg.archivePath());
            evidence.addOccurrence(occ);
        }
        if (identity != null) {
            evidence.setIdentities(List.of(identity));
        }
        return evidence;
    }

    /**
     * Sets the identity of a later instance of an already-rendered component
     * when the rendered one has none.
     */
    private void applyIdentityIfAbsent(Component component, PackageComponent pkg) {
        Evidence evidence = component.getEvidence();
        if (evidence != null && evidence.getIdentities() != null && !evidence.getIdentities().isEmpty()) {
            return;
        }
        Identity identity = identityOf(pkg);
        if (identity == null) {
            return;
        }
        if (evidence == null) {
            evidence = new Evidence();
            component.setEvidence(evidence);
        }
        evidence.setIdentities(List.of(identity));
    }

    /**
     * Maps a component's {@link Identification} to a CycloneDX purl identity
     * with a single method and no value, or {@code null} when the component
     * has none. The CycloneDX schema requires
     * {@code confidence} on each method as well as on the identity.
     */
    private Identity identityOf(PackageComponent pkg) {
        return pkg.identification() == null ? null : toIdentity(pkg.identification());
    }

    /**
     * Renders an {@link Identification} as a CycloneDX purl identity with a
     * single method and no value.
     *
     * @param identification how a component was identified
     * @return the identity
     */
    static Identity toIdentity(Identification identification) {
        Method method = new Method();
        method.setTechnique(Method.Technique.valueOf(identification.technique().name()));
        method.setConfidence(identification.confidence());

        Identity identity = new Identity();
        identity.setField(Identity.Field.PURL);
        identity.setConfidence(identification.confidence());
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
        ctx.byId.put(file.id(), comp);
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
                result.add(createPackageComponent(pkg, ctx));
            } else if (neutralComp instanceof FileComponent file) {
                result.add(createFileComponent(file, ctx));
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
     * Populates the BOM's dependency section from the model's
     * {@link DependencyEdge}s.
     *
     * <ul>
     * <li>The main component depends on every top-level component that no
     * edge points to (the others are reached through their dependents).</li>
     * <li>Every edge's parent gets an entry listing the bom-refs of its
     * children, each once.</li>
     * <li>Every other package component whose dependencies are known, and
     * every top-level file component, gets an empty (leaf) entry.</li>
     * <li>A component whose dependencies are unknown and from which no edge
     * starts gets no entry: an empty one would declare that it has none.</li>
     * </ul>
     *
     * <p>
     * Edges are resolved by id, so they connect exactly the copies they name.
     * An edge naming an id that is not in the model (e.g. a component a
     * transform dropped) is skipped. Entries, and each entry's children, are
     * sorted by ref.
     * </p>
     */
    private void buildDependencyTree(Bom bom, String mainBomRef, AssemblyComponents model, RenderContext ctx) {
        // Children kept as bom-refs in a sorted set: two ids of one merged
        // top-level component resolve to one ref, listed once.
        Map<Component, Set<String>> childRefsByParent = new IdentityHashMap<>();
        Set<Component> edgeTargets = Collections.newSetFromMap(new IdentityHashMap<>());
        for (DependencyEdge edge : model.dependencyEdges()) {
            Component parent = ctx.byId.get(edge.parent());
            Component child = ctx.byId.get(edge.child());
            if (parent == null || child == null) {
                continue;
            }
            childRefsByParent.computeIfAbsent(parent, k -> new TreeSet<>()).add(child.getBomRef());
            edgeTargets.add(child);
        }

        List<Dependency> dependencies = new ArrayList<>(ctx.packages.size() + ctx.components.size() + 1);
        Set<String> emitted = new HashSet<>();
        Set<String> mainChildren = new TreeSet<>();
        for (Component comp : ctx.components) {
            if (!edgeTargets.contains(comp)) {
                mainChildren.add(comp.getBomRef());
            }
        }
        dependencies.add(dependencyOf(mainBomRef, mainChildren));
        emitted.add(mainBomRef);
        for (Map.Entry<Component, Set<String>> e : childRefsByParent.entrySet()) {
            String ref = e.getKey().getBomRef();
            if (emitted.add(ref)) {
                dependencies.add(dependencyOf(ref, e.getValue()));
            }
        }
        for (Component comp : ctx.packages) {
            if (ctx.knownDependencies.contains(comp) && emitted.add(comp.getBomRef())) {
                dependencies.add(new Dependency(comp.getBomRef()));
            }
        }
        for (Component comp : ctx.components) {
            if (comp.getType() == Component.Type.FILE && emitted.add(comp.getBomRef())) {
                dependencies.add(new Dependency(comp.getBomRef()));
            }
        }
        dependencies.sort(Comparator.comparing(Dependency::getRef));
        bom.setDependencies(dependencies);
    }

    /**
     * Creates a dependency entry for {@code ref} listing {@code childRefs}, in
     * their iteration order.
     */
    private static Dependency dependencyOf(String ref, Set<String> childRefs) {
        Dependency dep = new Dependency(ref);
        for (String childRef : childRefs) {
            dep.addDependency(new Dependency(childRef));
        }
        return dep;
    }

    /**
     * Rendering context holding intermediate state and lookup maps.
     */
    private static class RenderContext {
        final Hash.Algorithm hashAlgorithm;
        final String normalizedAlg;
        final AssemblyMetadata metadata;

        /** The top-level components, in model order. */
        final List<Component> components = new ArrayList<>();
        /** Every rendered package component, top-level and nested. */
        final List<Component> packages = new ArrayList<>();
        /**
         * The rendered component of every model copy, by id. Top-level copies
         * merged by occurrence map to the one merged component.
         */
        final Map<ComponentId, Component> byId = new HashMap<>();
        /**
         * Rendered package components whose dependencies are known, compared
         * by identity (CycloneDX components compare by value, and two copies of
         * an artifact may be equal). Only these get leaf dependency entries.
         */
        final Set<Component> knownDependencies = Collections.newSetFromMap(new IdentityHashMap<>());
        /** Nested components by parent, compared by identity for the same reason. */
        final Map<Component, List<Component>> nestedComponentsByParent = new IdentityHashMap<>();

        /**
         * Creates the state of one rendering.
         *
         * @param hashAlgorithm the algorithm of the rendered hashes
         * @param normalizedAlg the normalized name of that algorithm
         * @param metadata the assembly metadata
         */
        RenderContext(Hash.Algorithm hashAlgorithm, String normalizedAlg, AssemblyMetadata metadata) {
            this.hashAlgorithm = hashAlgorithm;
            this.normalizedAlg = normalizedAlg;
            this.metadata = metadata;
        }
    }
}
