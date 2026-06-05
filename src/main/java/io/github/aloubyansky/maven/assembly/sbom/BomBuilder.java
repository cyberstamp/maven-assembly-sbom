package io.github.aloubyansky.maven.assembly.sbom;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.metadata.ToolInformation;

/**
 * Incrementally assembles a CycloneDX {@link Bom} from Maven artifacts and
 * arbitrary files discovered inside an assembly archive.
 *
 * <p>
 * Callers register components via {@link #addMavenArtifact} and
 * {@link #addFile}, optionally supply a dependency graph with
 * {@link #setDependencyGraph} and {@link #addExplicitDependency}, then
 * obtain the finished model with {@link #build()}.
 * </p>
 *
 * <p>
 * Duplicate Maven artifacts (same groupId:artifactId:version:classifier)
 * are merged: only the first registration creates a component, subsequent
 * calls add an additional {@link Occurrence} to the existing component's
 * evidence.
 * </p>
 */
public class BomBuilder {

    private static final Comparator<Component> COMPONENT_ORDER;
    static {
        Comparator<String> nullSafe = Comparator.nullsFirst(Comparator.naturalOrder());
        COMPONENT_ORDER = Comparator
                .comparing(Component::getGroup, nullSafe)
                .thenComparing(Component::getName)
                .thenComparing(Component::getVersion, nullSafe);
    }

    private final String projectGroupId;
    private final String projectArtifactId;
    private final String projectVersion;
    private final String assemblyId;
    private final Date timestamp;
    private final Hash.Algorithm hashAlgorithm;
    private final String hashAlgorithmName;

    private final List<Component> components = new ArrayList<>();
    private final Map<ArtifactCoords, String> bomRefById = new HashMap<>();
    private final Map<ArtifactCoords, Component> componentsById = new HashMap<>();
    private final Map<ArtifactCoords, List<Component>> nestedComponentsByParent = new HashMap<>();
    private final Map<String, Component> fileComponentsByPath = new HashMap<>();
    private final Map<String, List<Component>> nestedComponentsByFile = new HashMap<>();
    private final Set<String> directChildren = new HashSet<>();
    private final Map<ArtifactCoords, Set<ArtifactCoords>> explicitDeps = new HashMap<>();
    private LicenseChoice projectLicenses;
    private LicenseChoice toolLicenses;
    private String toolHash;
    private String archiveType;
    private String classifier;
    private Map<ArtifactCoords, List<ArtifactCoords>> artifactDependencyGraph;

    /**
     * Creates a builder for the given project coordinates, using the current
     * time as the BOM timestamp and SHA-256 as the hash algorithm.
     *
     * @param projectGroupId the project's Maven groupId
     * @param projectArtifactId the project's Maven artifactId
     * @param projectVersion the project's version
     * @param assemblyId the assembly descriptor id (used in the serial number seed)
     */
    public BomBuilder(String projectGroupId, String projectArtifactId,
            String projectVersion, String assemblyId) {
        this(projectGroupId, projectArtifactId, projectVersion, assemblyId, null,
                Hash.Algorithm.SHA_256);
    }

    /**
     * Creates a builder for the given project coordinates, explicit timestamp,
     * and hash algorithm.
     *
     * @param projectGroupId the project's Maven groupId
     * @param projectArtifactId the project's Maven artifactId
     * @param projectVersion the project's version
     * @param assemblyId the assembly descriptor id (used in the serial number seed)
     * @param timestamp the BOM metadata timestamp, or {@code null} to use the current time
     * @param hashAlgorithm the hash algorithm to use for component hashes
     */
    public BomBuilder(String projectGroupId, String projectArtifactId,
            String projectVersion, String assemblyId, Date timestamp,
            Hash.Algorithm hashAlgorithm) {
        this.projectGroupId = projectGroupId;
        this.projectArtifactId = projectArtifactId;
        this.projectVersion = projectVersion;
        this.assemblyId = assemblyId;
        this.timestamp = timestamp;
        this.hashAlgorithm = hashAlgorithm;
        this.hashAlgorithmName = hashAlgorithm.getSpec().replace("-", "").toLowerCase();
    }

    /**
     * Registers a Maven artifact as a {@link Component.Type#LIBRARY LIBRARY} component.
     *
     * <p>
     * If an artifact with the same coordinates has already been registered,
     * no new component is created. Instead, the given {@code archivePath} is
     * appended as an additional {@link Occurrence} on the existing component's
     * evidence. If the existing component has no licenses and the new call
     * provides them, the licenses are set.
     * </p>
     *
     * @param coords the Maven artifact coordinates
     * @param archivePath the path inside the assembly archive where this artifact appears,
     *        or {@code null} if the artifact was detected but not directly present
     * @param hash the hex-encoded content hash of the artifact file, or {@code null}
     * @param licenses the resolved license information, or {@code null} if unavailable
     */
    public void addMavenArtifact(ArtifactCoords coords, String archivePath,
            String hash, LicenseChoice licenses) {
        if (registerOrMergeMavenComponent(coords, archivePath, hash, licenses)) {
            Component comp = componentsById.get(coords);
            directChildren.add(comp.getBomRef());
            components.add(comp);
        }
    }

    /**
     * Registers a Maven artifact as a nested sub-component of an existing
     * parent component (e.g. a JAR nested inside an unpacked WAR).
     *
     * <p>
     * Unlike {@link #addMavenArtifact}, the resulting component is not
     * added to the top-level component list. Instead it is attached to the
     * parent component's {@code components} list during {@link #build()},
     * expressing a containment relationship in the CycloneDX model.
     * </p>
     *
     * <p>
     * If an artifact with identical coordinates already exists (at any
     * nesting level), the {@code archivePath} is appended as an additional
     * {@link Occurrence} and the existing component is added to the
     * parent's containment list.
     * </p>
     *
     * @param parentId the artifact identity of the containing component
     * @param coords the Maven artifact coordinates
     * @param archivePath the path relative to the distribution root where this
     *        artifact appears
     * @param hash the hex-encoded content hash, or {@code null}
     * @param licenses the resolved license information, or {@code null}
     */
    public void addNestedMavenArtifact(ArtifactCoords parentId, ArtifactCoords coords,
            String archivePath, String hash,
            LicenseChoice licenses) {
        registerOrMergeMavenComponent(coords, archivePath, hash, licenses);
        Component comp = componentsById.get(coords);
        if (comp != null) {
            nestedComponentsByParent.computeIfAbsent(parentId, k -> new ArrayList<>())
                    .add(comp);
        }
    }

    /**
     * Ensures a Maven component is registered for the given coordinates.
     * If the component already exists, merges the occurrence and licenses.
     *
     * @return {@code true} if a new component was created
     */
    private boolean registerOrMergeMavenComponent(ArtifactCoords coords, String archivePath,
            String hash, LicenseChoice licenses) {
        Component existing = componentsById.get(coords);
        if (existing != null) {
            appendOccurrence(existing, archivePath);
            applyLicensesIfAbsent(existing, licenses);
            return false;
        }

        Component comp = createMavenComponent(coords);
        if (hash != null) {
            comp.addHash(new Hash(hashAlgorithm, hash));
        }
        comp.setEvidence(buildMavenEvidence(archivePath));
        if (licenses != null) {
            comp.setLicenseChoice(licenses);
        }

        bomRefById.put(coords, comp.getBomRef());
        componentsById.put(coords, comp);
        return true;
    }

    /**
     * Registers a non-Maven file as a {@link Component.Type#FILE FILE} component.
     *
     * @param archivePath the path inside the assembly archive
     * @param hash the hex-encoded content hash, or {@code null}
     */
    public void addFile(String archivePath, String hash) {
        Component comp = createFileComponent(archivePath, hash);
        comp.setEvidence(buildFileEvidence(archivePath));
        if (projectLicenses != null) {
            comp.setLicenseChoice(projectLicenses);
        }
        directChildren.add(comp.getBomRef());
        components.add(comp);
        fileComponentsByPath.put(archivePath, comp);
    }

    /**
     * Registers a Maven artifact as a nested sub-component of a FILE
     * component (e.g. an artifact discovered via pom.properties inside
     * a shaded JAR that could not be positively identified as the owner).
     *
     * @param filePath the archive path of the parent FILE component
     * @param coords the Maven artifact coordinates
     * @param licenses the resolved license information, or {@code null}
     */
    public void addNestedArtifactUnderFile(String filePath, ArtifactCoords coords,
            LicenseChoice licenses) {
        registerOrMergeMavenComponent(coords, filePath, null, licenses);
        Component comp = componentsById.get(coords);
        if (comp != null) {
            nestedComponentsByFile.computeIfAbsent(filePath, k -> new ArrayList<>())
                    .add(comp);
        }
    }

    /**
     * Sets the license information for the project that owns the assembly.
     *
     * @param licenses the project's license information, or {@code null}
     */
    public void setProjectLicenses(LicenseChoice licenses) {
        this.projectLicenses = licenses;
    }

    /**
     * Sets the license information for the SBOM generator tool component.
     *
     * @param licenses the tool's license information, or {@code null}
     */
    public void setToolLicenses(LicenseChoice licenses) {
        this.toolLicenses = licenses;
    }

    /**
     * Sets the content hash of the SBOM generator tool JAR.
     *
     * @param hash the hex-encoded content hash, or {@code null}
     */
    public void setToolHash(String hash) {
        this.toolHash = hash;
    }

    /**
     * Sets the archive packaging type for the main component's PURL.
     *
     * @param archiveType the archive type (e.g. {@code "zip"}, {@code "tar.gz"}),
     *        or {@code null}
     */
    public void setArchiveType(String archiveType) {
        this.archiveType = archiveType;
    }

    /**
     * Sets the classifier for the main component's PURL.
     *
     * @param classifier the Maven classifier (typically the assembly id),
     *        or {@code null}
     */
    public void setClassifier(String classifier) {
        this.classifier = classifier;
    }

    /**
     * Sets the dependency graph collected from Maven dependency resolution.
     *
     * @param graph the dependency graph, keyed by parent artifact id
     */
    public void setDependencyGraph(Map<ArtifactCoords, List<ArtifactCoords>> graph) {
        this.artifactDependencyGraph = graph;
    }

    /**
     * Records an explicit parent-child dependency edge between two artifacts.
     *
     * @param parent the artifact id of the parent (e.g. the WAR)
     * @param child the artifact id of the child (e.g. a nested JAR)
     */
    public void addExplicitDependency(ArtifactCoords parent, ArtifactCoords child) {
        explicitDeps.computeIfAbsent(parent, k -> new HashSet<>()).add(child);
    }

    /**
     * Builds and returns the final CycloneDX {@link Bom}.
     *
     * @return the assembled BOM model, ready for serialization
     */
    public Bom build() {
        Bom bom = new Bom();
        bom.setSerialNumber(generateSerialNumber());

        attachNestedComponents();

        Component mainComponent = createMainComponent();
        bom.setMetadata(createMetadata(mainComponent));
        bom.setComponents(buildSortedComponentList());
        buildDependencyTree(bom, mainComponent.getBomRef());

        return bom;
    }

    /**
     * Attaches nested components to their parent components, establishing
     * the CycloneDX containment hierarchy. Each parent's nested list is
     * sorted by group/name/version for deterministic output.
     */
    private void attachNestedComponents() {
        Map<Component, List<Component>> merged = new HashMap<>();
        for (Map.Entry<ArtifactCoords, List<Component>> entry : nestedComponentsByParent.entrySet()) {
            Component parent = componentsById.get(entry.getKey());
            if (parent != null) {
                merged.computeIfAbsent(parent, k -> new ArrayList<>())
                        .addAll(entry.getValue());
            }
        }
        for (Map.Entry<String, List<Component>> entry : nestedComponentsByFile.entrySet()) {
            Component parent = fileComponentsByPath.get(entry.getKey());
            if (parent != null) {
                merged.computeIfAbsent(parent, k -> new ArrayList<>())
                        .addAll(entry.getValue());
            }
        }
        for (Map.Entry<Component, List<Component>> entry : merged.entrySet()) {
            List<Component> nested = entry.getValue();
            nested.sort(COMPONENT_ORDER);
            entry.getKey().setComponents(nested);
        }
    }

    /**
     * Generates a deterministic UUID-based serial number from the project
     * coordinates and assembly id.
     */
    private String generateSerialNumber() {
        StringBuilder seed = new StringBuilder();
        seed.append(projectGroupId).append(':').append(projectArtifactId)
                .append(':').append(projectVersion).append(':').append(assemblyId);
        if (archiveType != null) {
            seed.append(':').append(archiveType);
        }
        if (classifier != null) {
            seed.append(':').append(classifier);
        }
        return "urn:uuid:" + UUID.nameUUIDFromBytes(seed.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Creates the BOM metadata with timestamp, main component, and tool identity.
     */
    private Metadata createMetadata(Component mainComponent) {
        Metadata metadata = new Metadata();
        metadata.setTimestamp(timestamp != null ? timestamp : new Date());
        metadata.setComponent(mainComponent);
        metadata.setToolChoice(createToolInfo());
        return metadata;
    }

    /**
     * Creates the tool identity for the BOM metadata.
     */
    private ToolInformation createToolInfo() {
        Component tool = new Component();
        tool.setType(Component.Type.APPLICATION);
        tool.setGroup(ToolInfo.GROUP_ID);
        tool.setName(ToolInfo.ARTIFACT_ID);
        tool.setVersion(ToolInfo.VERSION);
        tool.setPurl(buildMavenPurl(ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID,
                ToolInfo.VERSION, "jar", null));
        if (toolLicenses != null) {
            tool.setLicenseChoice(toolLicenses);
        }
        if (toolHash != null) {
            tool.addHash(new Hash(hashAlgorithm, toolHash));
        }
        ToolInformation info = new ToolInformation();
        info.setComponents(List.of(tool));
        return info;
    }

    /**
     * Builds the complete component list sorted by group, name, version.
     */
    private List<Component> buildSortedComponentList() {
        List<Component> allComponents = new ArrayList<>(components);
        allComponents.sort(COMPONENT_ORDER);
        return allComponents;
    }

    // ---- component factories ----

    /**
     * Creates the top-level APPLICATION component representing the
     * assembly project itself.
     */
    private Component createMainComponent() {
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setGroup(projectGroupId);
        main.setName(projectArtifactId);
        main.setVersion(projectVersion);
        String purl = buildMainPurl();
        main.setBomRef(purl);
        main.setPurl(purl);
        if (projectLicenses != null) {
            main.setLicenseChoice(projectLicenses);
        }
        return main;
    }

    /**
     * Creates a LIBRARY component for a Maven artifact.
     */
    private Component createMavenComponent(ArtifactCoords coords) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(coords.groupId());
        comp.setName(coords.artifactId());
        comp.setVersion(coords.version());
        String purl = buildMavenPurl(coords.groupId(), coords.artifactId(),
                coords.version(), coords.type(), coords.classifier());
        comp.setBomRef(purl);
        comp.setPurl(purl);
        return comp;
    }

    /**
     * Creates a FILE component for a non-Maven file.
     */
    private Component createFileComponent(String archivePath, String hash) {
        Component comp = new Component();
        comp.setType(Component.Type.FILE);
        String fileName = SbomUtils.extractFileName(archivePath);
        comp.setName(fileName);
        comp.setBomRef("file:" + archivePath);
        comp.setPurl(buildGenericPurl(fileName, hash));
        if (hash != null) {
            comp.addHash(new Hash(hashAlgorithm, hash));
        }
        return comp;
    }

    /**
     * Sets license information on a component only if it does not already
     * have any.
     */
    private void applyLicensesIfAbsent(Component component, LicenseChoice licenses) {
        if (licenses != null && component.getLicenseChoice() == null) {
            component.setLicenseChoice(licenses);
        }
    }

    /**
     * Appends an additional {@link Occurrence} to an already-registered
     * component.
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
     * Builds evidence for a Maven artifact including an identity assertion
     * and an optional occurrence.
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
     */
    private Identity buildMavenIdentity() {
        Identity identity = new Identity();
        identity.setField(Identity.Field.PURL);
        identity.setConfidence(1.0);
        Method method = new Method();
        method.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        method.setValue("maven-pom-analysis");
        identity.setMethods(List.of(method));
        return identity;
    }

    /**
     * Builds evidence for a non-Maven file with its archive location.
     */
    private Evidence buildFileEvidence(String archivePath) {
        Evidence evidence = new Evidence();
        Occurrence occ = new Occurrence();
        occ.setLocation(archivePath);
        evidence.addOccurrence(occ);
        return evidence;
    }

    /**
     * Populates the BOM's dependency section from the registered
     * dependency graph and explicit dependencies.
     */
    private void buildDependencyTree(Bom bom, String mainBomRef) {
        Dependency mainDep = buildMainDependency(mainBomRef);
        bom.addDependency(mainDep);
        addInterArtifactDependencies(bom);
        addFileDependencyEntries(bom);
        bom.getDependencies().sort(Comparator.comparing(Dependency::getRef));
    }

    /**
     * Creates the dependency entry for the main component, listing only
     * direct (non-transitive) children.
     */
    private Dependency buildMainDependency(String mainBomRef) {
        Set<String> transitiveChildren = collectTransitiveChildren();
        Dependency mainDep = new Dependency(mainBomRef);
        directChildren.stream()
                .filter(ref -> !transitiveChildren.contains(ref))
                .sorted()
                .forEach(ref -> mainDep.addDependency(new Dependency(ref)));
        return mainDep;
    }

    /**
     * Collects all bom-refs that appear as a child in any dependency edge.
     */
    private Set<String> collectTransitiveChildren() {
        Set<String> transitiveChildren = new HashSet<>();
        collectTransitiveChildrenFrom(artifactDependencyGraph, transitiveChildren);
        collectTransitiveChildrenFrom(explicitDeps, transitiveChildren);
        return transitiveChildren;
    }

    /**
     * Adds all child bom-refs from the given dependency map to the
     * accumulator set.
     */
    private void collectTransitiveChildrenFrom(
            Map<ArtifactCoords, ? extends Iterable<ArtifactCoords>> depMap,
            Set<String> accumulator) {
        if (depMap == null) {
            return;
        }
        for (Iterable<ArtifactCoords> deps : depMap.values()) {
            for (ArtifactCoords depId : deps) {
                String ref = bomRefById.get(depId);
                if (ref != null) {
                    accumulator.add(ref);
                }
            }
        }
    }

    /**
     * Merges the resolved dependency graph and explicit dependencies,
     * then adds a dependency entry for each parent artifact.
     */
    private void addInterArtifactDependencies(Bom bom) {
        Map<ArtifactCoords, Set<ArtifactCoords>> merged = mergeDependencyGraphs();
        if (merged.isEmpty()) {
            return;
        }
        for (Map.Entry<ArtifactCoords, Set<ArtifactCoords>> entry : merged.entrySet()) {
            String parentRef = bomRefById.get(entry.getKey());
            if (parentRef == null) {
                continue;
            }
            Dependency dep = new Dependency(parentRef);
            resolveChildRefs(entry.getValue()).forEach(
                    childRef -> dep.addDependency(new Dependency(childRef)));
            bom.addDependency(dep);
        }
    }

    /**
     * Merges the resolved Maven dependency graph and the explicit
     * dependency map into a single map.
     */
    private Map<ArtifactCoords, Set<ArtifactCoords>> mergeDependencyGraphs() {
        int estimatedSize = (artifactDependencyGraph != null ? artifactDependencyGraph.size() : 0)
                + explicitDeps.size();
        Map<ArtifactCoords, Set<ArtifactCoords>> merged = new HashMap<>(estimatedSize);
        if (artifactDependencyGraph != null) {
            for (Map.Entry<ArtifactCoords, List<ArtifactCoords>> e : artifactDependencyGraph.entrySet()) {
                merged.computeIfAbsent(e.getKey(), k -> new HashSet<>(e.getValue().size()))
                        .addAll(e.getValue());
            }
        }
        for (Map.Entry<ArtifactCoords, Set<ArtifactCoords>> e : explicitDeps.entrySet()) {
            merged.computeIfAbsent(e.getKey(), k -> new HashSet<>(e.getValue().size()))
                    .addAll(e.getValue());
        }
        return merged;
    }

    /**
     * Resolves artifact ids to bom-refs, filtering out unknown artifacts,
     * returning sorted results.
     */
    private List<String> resolveChildRefs(Set<ArtifactCoords> childIds) {
        List<String> childRefs = new ArrayList<>(childIds.size());
        for (ArtifactCoords childId : childIds) {
            String childRef = bomRefById.get(childId);
            if (childRef != null) {
                childRefs.add(childRef);
            }
        }
        childRefs.sort(Comparator.naturalOrder());
        return childRefs;
    }

    /**
     * Adds empty (leaf-node) dependency entries for all FILE components.
     */
    private void addFileDependencyEntries(Bom bom) {
        for (Component comp : components) {
            if (comp.getType() == Component.Type.FILE) {
                bom.addDependency(new Dependency(comp.getBomRef()));
            }
        }
    }

    // ---- PURL builders ----

    /**
     * Builds the Package URL for the main assembly component.
     * When no archive type is set (e.g., directory assembly), returns
     * a bare {@code pkg:maven/g/a@v} without type or classifier.
     */
    private String buildMainPurl() {
        String base = "pkg:maven/" + purlEncode(projectGroupId) + "/"
                + purlEncode(projectArtifactId) + "@" + purlEncode(projectVersion);
        if (archiveType == null) {
            return base;
        }
        String purl = base + "?type=" + purlEncode(archiveType);
        if (classifier != null && !classifier.isEmpty()) {
            purl += "&classifier=" + purlEncode(classifier);
        }
        return purl;
    }

    /**
     * Builds a Package URL for a Maven artifact.
     */
    private static String buildMavenPurl(String groupId, String artifactId,
            String version, String type, String classifier) {
        String purl = "pkg:maven/" + purlEncode(groupId) + "/" + purlEncode(artifactId)
                + "@" + purlEncode(version)
                + "?type=" + purlEncode(type != null ? type : "jar");
        if (classifier != null && !classifier.isEmpty()) {
            purl += "&classifier=" + purlEncode(classifier);
        }
        return purl;
    }

    /**
     * Builds a Package URL for a generic (non-Maven) file.
     */
    private String buildGenericPurl(String fileName, String hash) {
        String purl = "pkg:generic/" + purlEncode(fileName);
        if (hash != null) {
            purl += "?checksum=" + purlEncode(hashAlgorithmName) + ":" + purlEncode(hash);
        }
        return purl;
    }

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    /**
     * Percent-encodes a PURL component per RFC 3986. Only unreserved
     * characters (A-Z a-z 0-9 - . _ ~) are left unencoded.
     */
    private static String purlEncode(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i);
            if (!isUnreserved(c)) {
                break;
            }
            i++;
        }
        if (i == value.length()) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append(value, 0, i);
        for (byte b : value.substring(i).getBytes(StandardCharsets.UTF_8)) {
            if (isUnreserved(b)) {
                sb.append((char) b);
            } else {
                int unsigned = b & 0xFF;
                sb.append('%');
                sb.append(HEX_DIGITS[unsigned >> 4]);
                sb.append(HEX_DIGITS[unsigned & 0x0F]);
            }
        }
        return sb.toString();
    }

    private static boolean isUnreserved(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
    }

}
