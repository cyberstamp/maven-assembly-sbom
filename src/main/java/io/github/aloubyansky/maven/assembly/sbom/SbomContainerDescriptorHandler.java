package io.github.aloubyansky.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.plugins.assembly.filter.ContainerDescriptorHandler;
import org.apache.maven.plugins.assembly.model.Assembly;
import org.apache.maven.plugins.assembly.model.io.xpp3.AssemblyXpp3Reader;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.archiver.ArchiveEntry;
import org.codehaus.plexus.archiver.Archiver;
import org.codehaus.plexus.archiver.ArchiverException;
import org.codehaus.plexus.archiver.ResourceIterator;
import org.codehaus.plexus.archiver.UnArchiver;
import org.codehaus.plexus.components.io.fileselectors.FileInfo;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Hash;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Maven Assembly Plugin {@link ContainerDescriptorHandler} that generates a
 * CycloneDX Software Bill of Materials (SBOM) during archive creation.
 *
 * <p>
 * The handler is registered under the name {@code "sbom"} and can be
 * referenced from an assembly descriptor's {@code <containerDescriptorHandlers>}
 * section. Artifact identification is delegated to {@link ArchiveAnalyzer};
 * this class handles configuration, archive scanning, dependency graph
 * construction, and BOM output.
 * </p>
 */
@Named("sbom")
public class SbomContainerDescriptorHandler implements ContainerDescriptorHandler {

    private static final Logger log = LoggerFactory.getLogger(SbomContainerDescriptorHandler.class);

    @Inject
    private MavenProject project;

    @Inject
    private MavenSession session;

    @Inject
    private RepositorySystem repoSystem;

    @Inject
    private EffectiveModelResolver effectiveModelResolver;

    private String format = "json";
    private String outputPath = "bom.cdx.json";
    private String output = "embedded";
    private String hashAlgorithm = "SHA-256";
    private boolean prettyPrint;
    private boolean failOnMissingLicense;
    private boolean failOnDuplicateHash = true;

    private MavenLicenseResolver licenseResolver;

    private boolean includeBaseDir;
    private String assemblyId;
    private String classifier;
    // not thread-safe — safe here because finalizeArchiveCreation is single-threaded
    private MessageDigest messageDigest;
    private Hash.Algorithm bomHashAlgorithm;
    private List<Dependency> cachedManagedDeps;

    /** Always returns {@code true} — this handler does not filter. */
    @Override
    public boolean isSelected(FileInfo fileInfo) throws IOException {
        return true;
    }

    /**
     * Intercepts archive creation to generate and embed a CycloneDX SBOM.
     *
     * @param archiver the archiver being built
     * @throws ArchiverException if SBOM generation fails
     */
    @Override
    public void finalizeArchiveCreation(Archiver archiver) throws ArchiverException {
        try {
            initConfig(archiver);
            effectiveModelResolver.init(
                    session.getRepositorySession(),
                    project.getRemoteProjectRepositories(),
                    session.getProjects());
            licenseResolver = new MavenLicenseResolver(
                    effectiveModelResolver, failOnMissingLicense);
            cachedManagedDeps = null;

            List<ArchiveContent.FileEntry> entries = collectArchiveEntries(archiver);
            String baseDirPrefix = detectBaseDirPrefix(entries);
            ArchiveContent content = analyzeEntries(entries, baseDirPrefix);

            BomBuilder builder = new BomBuilder(
                    project.getGroupId(), project.getArtifactId(),
                    project.getVersion(), assemblyId,
                    SbomUtils.parseBuildTimestamp(getTimestamp()), bomHashAlgorithm);
            builder.setProjectLicenses(licenseResolver.resolveLicenses(
                    project.getGroupId(), project.getArtifactId(),
                    project.getVersion()));
            builder.setClassifier(classifier);
            builder.setArchiveType(detectArchiveType(archiver));
            populateToolMetadata(builder);

            addToBom(content, builder);

            Bom bom = builder.build();
            if (log.isDebugEnabled()) {
                logBomSummary(bom);
            }
            writeBomOutput(bom, baseDirPrefix, archiver);

        } catch (LicenseResolutionException e) {
            throw new ArchiverException(e.getMessage(), e);
        } catch (ArchiverException e) {
            throw e;
        } catch (Exception e) {
            throw new ArchiverException("Failed to generate SBOM", e);
        }
    }

    private void addToBom(ArchiveContent content, BomBuilder builder) {
        for (var e : content.mavenEntries()) {
            ArtifactCoords id = e.artifactId();
            builder.addMavenArtifact(id, e.archivePath(), e.hash(),
                    licenseResolver.resolveLicenses(
                            id.groupId(), id.artifactId(), id.version()));
        }
        for (var e : content.nestedEntries()) {
            ArtifactCoords id = e.artifactId();
            builder.addNestedMavenArtifact(e.parentId(), id, e.archivePath(), e.hash(),
                    licenseResolver.resolveLicenses(
                            id.groupId(), id.artifactId(), id.version()));
        }
        for (var edge : content.explicitDependencies()) {
            builder.addExplicitDependency(edge.parent(), edge.child());
        }
        for (var e : content.unmatchedFiles()) {
            builder.addFile(e.path(), e.hash());
        }
        for (var e : content.fileNestedArtifacts()) {
            ArtifactCoords id = e.artifactId();
            builder.addNestedArtifactUnderFile(e.filePath(), id,
                    licenseResolver.resolveLicenses(
                            id.groupId(), id.artifactId(), id.version()));
        }
        buildDependencyGraph(builder, content);
    }

    private String getTimestamp() {
        return project.getProperties() != null
                ? project.getProperties().getProperty("project.build.outputTimestamp")
                : null;
    }

    private ArchiveContent analyzeEntries(List<ArchiveContent.FileEntry> entries, String baseDirPrefix) {
        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem,
                project, session, messageDigest, failOnDuplicateHash);
        return analyzer.analyze(entries, baseDirPrefix);
    }

    /**
     * Initializes per-archive configuration.
     */
    private void initConfig(Archiver archiver) throws ArchiverException {
        if (!"json".equalsIgnoreCase(format) && !"xml".equalsIgnoreCase(format)) {
            throw new ArchiverException(
                    "Unsupported SBOM format: " + format + ". Supported values: json, xml");
        }
        if (!isEmbedded() && !isExternal()) {
            throw new ArchiverException(
                    "Unsupported output mode: " + output
                            + ". Supported values: embedded, external, all");
        }
        AssemblyConfig assemblyConfig = resolveAssemblyConfig(archiver);
        includeBaseDir = assemblyConfig.assembly == null
                || assemblyConfig.assembly.isIncludeBaseDirectory();
        assemblyId = assemblyConfig.assembly != null
                ? assemblyConfig.assembly.getId()
                : "assembly";
        classifier = assemblyConfig.classifier;
        try {
            bomHashAlgorithm = Hash.Algorithm.fromSpec(hashAlgorithm);
        } catch (IllegalArgumentException e) {
            throw new ArchiverException("Hash algorithm '" + hashAlgorithm
                    + "' is not supported by the CycloneDX specification", e);
        }
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new ArchiverException("Unsupported hash algorithm: " + hashAlgorithm, e);
        }
    }

    /**
     * Resolves the license and content hash for the SBOM generator tool.
     * Failures are non-fatal.
     */
    private void populateToolMetadata(BomBuilder builder) {
        Properties toolProps = SbomUtils.loadToolProperties();
        builder.setToolProperties(toolProps);
        String toolGroupId = toolProps.getProperty("groupId");
        String toolArtifactCoords = toolProps.getProperty("artifactId");
        String toolVersion = toolProps.getProperty("version");
        if (toolGroupId == null || toolArtifactCoords == null || toolVersion == null) {
            return;
        }
        builder.setToolLicenses(licenseResolver.resolveLicenses(
                toolGroupId, toolArtifactCoords, toolVersion));
        resolveToolHash(builder, toolGroupId, toolArtifactCoords, toolVersion);
    }

    /**
     * Resolves the tool's JAR artifact and computes its content hash.
     */
    private void resolveToolHash(BomBuilder builder, String groupId,
            String artifactId, String version) {
        try {
            org.eclipse.aether.artifact.DefaultArtifact toolArtifact = new org.eclipse.aether.artifact.DefaultArtifact(
                    groupId, artifactId, "jar", version);
            ArtifactRequest request = new ArtifactRequest(
                    toolArtifact, project.getRemoteProjectRepositories(), null);
            ArtifactResult result = repoSystem.resolveArtifact(
                    session.getRepositorySession(), request);
            File jarFile = result.getArtifact().getFile();
            if (jarFile != null && jarFile.isFile()) {
                builder.setToolHash(SbomUtils.computeHash(messageDigest, jarFile.toPath()));
            }
        } catch (Exception e) {
            log.debug("Could not resolve tool artifact {}:{}:{}",
                    groupId, artifactId, version, e);
        }
    }

    /**
     * Iterates all file entries in the archiver and computes their hashes.
     */
    private List<ArchiveContent.FileEntry> collectArchiveEntries(Archiver archiver)
            throws IOException {
        List<ArchiveContent.FileEntry> entries = new ArrayList<>();
        for (ResourceIterator it = archiver.getResources(); it.hasNext();) {
            ArchiveEntry ae = it.next();
            if (ae.getType() != ArchiveEntry.FILE) {
                continue;
            }
            try (InputStream is = ae.getInputStream()) {
                entries.add(new ArchiveContent.FileEntry(ae.getName(), SbomUtils.computeHash(messageDigest, is)));
            }
        }
        return entries;
    }

    /**
     * Detects the base directory prefix from the first archive entry.
     *
     * <p>
     * Relies on the first file entry in the archive iterator. Under
     * the default Maven Assembly Plugin entry ordering this is reliable.
     * Custom archiver plugins that reorder entries could produce an
     * incorrect prefix.
     * </p>
     *
     * @return the prefix including trailing slash, or {@code null}
     */
    private String detectBaseDirPrefix(List<ArchiveContent.FileEntry> entries) {
        if (!includeBaseDir || entries.isEmpty()) {
            return null;
        }
        String firstPath = entries.get(0).path();
        int slash = firstPath.indexOf('/');
        return slash > 0 ? firstPath.substring(0, slash + 1) : null;
    }

    /**
     * Resolved assembly descriptor and classifier.
     */
    private record AssemblyConfig(Assembly assembly, String classifier) {
    }

    /**
     * Locates the assembly descriptor that produced the archive and
     * resolves the artifact classifier from the plugin configuration.
     *
     * <p>
     * The classifier is determined by the assembly plugin's
     * {@code appendAssemblyId} and {@code classifier} settings:
     * if an explicit {@code classifier} is configured, it is used;
     * otherwise, the assembly id is used as the classifier unless
     * {@code appendAssemblyId} is set to {@code false}.
     * </p>
     */
    private AssemblyConfig resolveAssemblyConfig(Archiver archiver) {
        try {
            File destFile = archiver.getDestFile();
            if (destFile == null) {
                return new AssemblyConfig(null, null);
            }
            String destName = destFile.getName();
            org.apache.maven.model.PluginExecution soleExec = null;
            Assembly soleAssembly = null;
            int candidateCount = 0;
            for (org.apache.maven.model.Plugin plugin : project.getBuild().getPlugins()) {
                if (!"maven-assembly-plugin".equals(plugin.getArtifactId())) {
                    continue;
                }
                String defaultFinalName = resolveFinalName(plugin.getConfiguration());
                for (org.apache.maven.model.PluginExecution exec : plugin.getExecutions()) {
                    List<Assembly> descriptors = findAllDescriptors(exec);
                    Assembly match = matchDescriptorByFilename(
                            exec, destName, defaultFinalName, descriptors);
                    if (match != null) {
                        String classifier = resolveClassifier(exec, match.getId());
                        return new AssemblyConfig(match, classifier);
                    }
                    for (Assembly candidate : descriptors) {
                        candidateCount++;
                        soleExec = exec;
                        soleAssembly = candidate;
                    }
                }
            }
            if (candidateCount == 1) {
                String classifier = resolveClassifier(soleExec, soleAssembly.getId());
                return new AssemblyConfig(soleAssembly, classifier);
            }
        } catch (Exception e) {
            log.debug("Could not locate assembly descriptor for {}", archiver.getDestFile(), e);
        }
        return new AssemblyConfig(null, null);
    }

    /**
     * Resolves the artifact classifier from the plugin execution config.
     */
    private static String resolveClassifier(org.apache.maven.model.PluginExecution exec,
            String assemblyId) {
        Object cfg = exec.getConfiguration();
        if (!(cfg instanceof org.codehaus.plexus.util.xml.Xpp3Dom dom)) {
            return assemblyId;
        }
        String explicit = getChildValue(dom, "classifier");
        if (explicit != null) {
            return explicit;
        }
        String appendId = getChildValue(dom, "appendAssemblyId");
        if ("false".equalsIgnoreCase(appendId)) {
            return null;
        }
        return assemblyId;
    }

    /**
     * Returns the text value of a child element, or {@code null}.
     */
    private static String getChildValue(org.codehaus.plexus.util.xml.Xpp3Dom dom,
            String childName) {
        org.codehaus.plexus.util.xml.Xpp3Dom child = dom.getChild(childName);
        if (child == null) {
            return null;
        }
        String val = child.getValue();
        return val != null && !val.isBlank() ? val.trim() : null;
    }

    /**
     * Matches a descriptor by reconstructing the expected archive
     * filename from {@code finalName} and {@code appendAssemblyId}.
     */
    private Assembly matchDescriptorByFilename(
            org.apache.maven.model.PluginExecution exec,
            String destName, String defaultFinalName, List<Assembly> descriptors) {
        String finalName = resolveFinalName(exec.getConfiguration(), defaultFinalName);
        boolean appendId = !"false".equalsIgnoreCase(
                getConfigValue(exec.getConfiguration(), "appendAssemblyId"));
        for (Assembly assembly : descriptors) {
            String expected = appendId
                    ? finalName + "-" + assembly.getId()
                    : finalName;
            if (destName.startsWith(expected + ".") || destName.equals(expected)) {
                return assembly;
            }
        }
        return null;
    }

    /**
     * Parses all valid assembly descriptors from a plugin execution.
     */
    private List<Assembly> findAllDescriptors(org.apache.maven.model.PluginExecution exec) {
        Object descCfg = exec.getConfiguration();
        if (descCfg == null) {
            return List.of();
        }
        List<Assembly> result = new ArrayList<>();
        for (String descriptorPath : extractDescriptorPaths(descCfg)) {
            Path descriptorFile = resolveDescriptorPath(descriptorPath);
            if (!Files.isRegularFile(descriptorFile)) {
                continue;
            }
            Assembly assembly = parseAssemblyDescriptor(descriptorFile);
            if (assembly != null && assembly.getId() != null) {
                result.add(assembly);
            }
        }
        return result;
    }

    private String resolveFinalName(Object config) {
        return resolveFinalName(config, project.getBuild().getFinalName());
    }

    private String resolveFinalName(Object config, String fallback) {
        String raw = getConfigValue(config, "finalName");
        if (raw == null) {
            return fallback;
        }
        return interpolate(raw);
    }

    /**
     * Reads a configuration value from a possibly-null config object.
     */
    private static String getConfigValue(Object config, String key) {
        if (config instanceof org.codehaus.plexus.util.xml.Xpp3Dom dom) {
            return getChildValue(dom, key);
        }
        return null;
    }

    /**
     * Resolves {@code ${...}} property expressions against the project
     * properties. Returns {@code null} if the input is {@code null} or
     * any expression cannot be resolved.
     */
    private String interpolate(String value) {
        if (value == null) {
            return null;
        }
        if (!value.contains("${")) {
            return value;
        }
        Properties props = project.getProperties();
        StringBuilder result = new StringBuilder();
        int pos = 0;
        while (pos < value.length()) {
            int start = value.indexOf("${", pos);
            if (start < 0) {
                result.append(value, pos, value.length());
                break;
            }
            result.append(value, pos, start);
            int end = value.indexOf('}', start + 2);
            if (end < 0) {
                return null;
            }
            String key = value.substring(start + 2, end);
            String resolved = props.getProperty(key);
            if (resolved == null) {
                resolved = resolveProjectExpression(key);
            }
            if (resolved == null) {
                return null;
            }
            result.append(resolved);
            pos = end + 1;
        }
        return result.toString();
    }

    private String resolveProjectExpression(String key) {
        return switch (key) {
            case "project.artifactId" -> project.getArtifactId();
            case "project.version" -> project.getVersion();
            case "project.groupId" -> project.getGroupId();
            case "project.build.finalName" -> project.getBuild().getFinalName();
            default -> null;
        };
    }

    /**
     * Resolves a descriptor path to an absolute path.
     */
    private Path resolveDescriptorPath(String descriptorPath) {
        Path path = Path.of(descriptorPath);
        if (!path.isAbsolute()) {
            path = project.getBasedir().toPath().resolve(descriptorPath);
        }
        return path;
    }

    /**
     * Parses an assembly descriptor XML file.
     */
    private Assembly parseAssemblyDescriptor(Path descriptorFile) {
        try (var reader = Files.newBufferedReader(descriptorFile, StandardCharsets.UTF_8)) {
            return new AssemblyXpp3Reader().read(reader);
        } catch (Exception e) {
            log.debug("Failed to parse assembly descriptor {}", descriptorFile, e);
            return null;
        }
    }

    /**
     * Extracts descriptor file paths from the plugin's Xpp3Dom config.
     */
    private List<String> extractDescriptorPaths(Object configuration) {
        List<String> paths = new ArrayList<>();
        if (configuration instanceof org.codehaus.plexus.util.xml.Xpp3Dom dom) {
            org.codehaus.plexus.util.xml.Xpp3Dom descriptors = dom.getChild("descriptors");
            if (descriptors != null) {
                for (org.codehaus.plexus.util.xml.Xpp3Dom desc : descriptors.getChildren("descriptor")) {
                    String val = desc.getValue();
                    if (val != null && !val.isBlank()) {
                        paths.add(val.trim());
                    }
                }
            }
        }
        return paths;
    }

    /**
     * Builds the Maven dependency graph and sets it on the builder.
     */
    private void buildDependencyGraph(BomBuilder builder, ArchiveContent content) {
        try {
            Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = collectDependencyEdges(content.nestedDepsByParent());
            Set<ArtifactCoords> knownIds = content.collectKnownArtifactCoords();
            Map<ArtifactCoords, List<ArtifactCoords>> graph = filterEdges(collectedEdges, knownIds);
            builder.setDependencyGraph(graph);
        } catch (Exception e) {
            log.warn("Failed to build dependency graph, SBOM will omit dependency information", e);
        }
    }

    /**
     * Performs dependency collection with an edge-collecting selector.
     */
    private Map<ArtifactCoords, Set<ArtifactCoords>> collectDependencyEdges(
            Map<ArtifactCoords, List<Dependency>> nestedDepsByParent) throws Exception {
        Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = new ConcurrentHashMap<>();

        DefaultRepositorySystemSession mutableSession = new DefaultRepositorySystemSession(
                session.getRepositorySession());
        mutableSession.setDependencySelector(new EdgeCollectorSelectorFactory(
                session.getRepositorySession().getDependencySelector(), collectedEdges));

        List<Dependency> projectManagedDeps = collectManagedDependencies();
        CollectRequest request = buildCollectRequest(
                toAetherDependencies(project.getDependencies()), projectManagedDeps);
        repoSystem.collectDependencies(mutableSession, request);

        for (Map.Entry<ArtifactCoords, List<Dependency>> entry : nestedDepsByParent.entrySet()) {
            List<Dependency> parentManagedDeps = resolveManagedDependencies(entry.getKey());
            CollectRequest nestedRequest = buildCollectRequest(entry.getValue(), parentManagedDeps);
            repoSystem.collectDependencies(mutableSession, nestedRequest);
        }

        return collectedEdges;
    }

    /**
     * Resolves dependency management entries for a component.
     */
    private List<Dependency> resolveManagedDependencies(ArtifactCoords coords) {
        Model model = effectiveModelResolver.resolveEffectiveModel(
                coords.groupId(), coords.artifactId(), coords.version());
        if (model == null || model.getDependencyManagement() == null
                || model.getDependencyManagement().getDependencies() == null) {
            return List.of();
        }
        return toAetherDependencies(model.getDependencyManagement().getDependencies());
    }

    /**
     * Returns the project's managed dependencies, caching the result.
     */
    private List<Dependency> collectManagedDependencies() {
        if (cachedManagedDeps != null) {
            return cachedManagedDeps;
        }
        List<Dependency> managedDeps;
        if (project.getDependencyManagement() != null
                && project.getDependencyManagement().getDependencies() != null) {
            managedDeps = toAetherDependencies(project.getDependencyManagement().getDependencies());
        } else {
            managedDeps = List.of();
        }
        cachedManagedDeps = managedDeps;
        return managedDeps;
    }

    /**
     * Converts Maven model dependencies to Aether dependencies.
     */
    private List<Dependency> toAetherDependencies(List<org.apache.maven.model.Dependency> deps) {
        List<Dependency> result = new ArrayList<>(deps.size());
        for (org.apache.maven.model.Dependency dep : deps) {
            result.add(toAetherDependency(dep));
        }
        return result;
    }

    /**
     * Creates a {@link CollectRequest} with the project's remote repos.
     */
    private CollectRequest buildCollectRequest(List<Dependency> deps,
            List<Dependency> managedDeps) {
        CollectRequest request = new CollectRequest();
        request.setDependencies(deps);
        request.setManagedDependencies(managedDeps);
        request.setRepositories(project.getRemoteProjectRepositories());
        return request;
    }

    /**
     * Filters dependency edges to only include assembly-present artifacts.
     */
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

    /**
     * Writes the BOM as an external file, embedded in the archive, or both,
     * depending on the configured {@code output} mode.
     */
    private void writeBomOutput(Bom bom, String baseDirPrefix, Archiver archiver)
            throws IOException, org.cyclonedx.exception.GeneratorException {
        Path externalBomPath = null;
        if (isExternal()) {
            externalBomPath = resolveExternalBomPath(archiver);
            if (externalBomPath != null) {
                Files.createDirectories(externalBomPath.getParent());
                writeBom(bom, externalBomPath);
            }
        }
        Path tempFile = null;
        if (isEmbedded()) {
            tempFile = writeBomToArchive(bom, baseDirPrefix, archiver);
        }
        if (externalBomPath != null || tempFile != null) {
            registerPostArchiveHook(archiver, bom, externalBomPath, tempFile);
        }
    }

    /**
     * Determines the external BOM file path from the archive destination.
     */
    private Path resolveExternalBomPath(Archiver archiver) {
        File destFile = archiver.getDestFile();
        if (destFile != null) {
            String suffix = "xml".equalsIgnoreCase(format) ? ".cdx.xml" : ".cdx.json";
            return destFile.toPath().resolveSibling(destFile.getName() + suffix);
        }
        return null;
    }

    /**
     * Registers a single post-archive closeable that updates the external
     * BOM with the archive hash and deletes the embedded BOM temp file.
     *
     * <p>
     * The Plexus Archiver API provides no public post-write hook.
     * This method accesses the internal {@code closeables} list via
     * reflection as a best-effort mechanism. If the field is missing
     * or inaccessible, a warning is logged and the BOM is
     * produced without the archive hash.
     * </p>
     */
    @SuppressWarnings("unchecked")
    private void registerPostArchiveHook(Archiver archiver, Bom bom,
            Path externalBomPath, Path tempFile) {
        try {
            java.lang.reflect.Field field = findField(archiver.getClass(), "closeables");
            if (field == null) {
                if (externalBomPath != null) {
                    log.warn("Could not find closeables field on archiver, "
                            + "archive hash will not be added to the external BOM");
                }
                return;
            }
            field.setAccessible(true);
            List<java.io.Closeable> closeables = (List<java.io.Closeable>) field.get(archiver);
            MessageDigest digest = messageDigest;
            Hash.Algorithm algorithm = bomHashAlgorithm;
            closeables.add(() -> {
                if (externalBomPath != null) {
                    updateBomWithArchiveHash(archiver, bom, externalBomPath, digest, algorithm);
                }
                if (tempFile != null) {
                    Files.deleteIfExists(tempFile);
                }
            });
        } catch (Exception e) {
            if (externalBomPath != null) {
                log.warn("Could not register post-archive hook, "
                        + "archive hash will not be added to the external BOM", e);
            }
        }
    }

    /**
     * Walks the class hierarchy to find a declared field by name.
     */
    private static java.lang.reflect.Field findField(Class<?> clazz, String name) {
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

    /**
     * Computes the archive's content hash and rewrites the BOM with it.
     */
    private void updateBomWithArchiveHash(Archiver archiver, Bom bom, Path bomPath,
            MessageDigest digest, Hash.Algorithm algorithm) {
        try {
            File archiveFile = archiver.getDestFile();
            if (archiveFile == null || !archiveFile.isFile()) {
                return;
            }
            String archiveHash = SbomUtils.computeHash(digest, archiveFile.toPath());
            bom.getMetadata().getComponent()
                    .addHash(new Hash(algorithm, archiveHash));
            writeBom(bom, bomPath);
            log.debug("Updated BOM with archive hash: {}", archiveHash);
        } catch (Exception e) {
            log.warn("Failed to update BOM with archive hash", e);
        }
    }

    /**
     * Writes the BOM to a temp file and adds it to the archive.
     *
     * @return the temp file path, for cleanup after the archive is written
     */
    private Path writeBomToArchive(Bom bom, String baseDirPrefix, Archiver archiver)
            throws IOException, org.cyclonedx.exception.GeneratorException {
        Path targetDir = Path.of(project.getBuild().getDirectory());
        Files.createDirectories(targetDir);
        Path tempFile = Files.createTempFile(targetDir, "assembly-sbom", ".cdx." + format);
        writeBom(bom, tempFile);
        String bomArchivePath = baseDirPrefix != null
                ? baseDirPrefix + outputPath
                : outputPath;
        archiver.addFile(tempFile.toFile(), bomArchivePath);
        return tempFile;
    }

    /**
     * Serializes the BOM in the configured format.
     */
    private void writeBom(Bom bom, Path output)
            throws IOException, org.cyclonedx.exception.GeneratorException {
        if ("xml".equalsIgnoreCase(format)) {
            BomWriter.writeXml(bom, output);
        } else {
            BomWriter.writeJson(bom, output, prettyPrint);
        }
    }

    /**
     * Logs a summary of the generated BOM.
     */
    private void logBomSummary(Bom bom) {
        long libCount = bom.getComponents().stream()
                .filter(c -> c.getType() == org.cyclonedx.model.Component.Type.LIBRARY).count();
        long fileCount = bom.getComponents().size() - libCount;
        log.debug("SBOM: {} libraries, {} files, {} dependency entries",
                libCount, fileCount,
                bom.getDependencies() != null ? bom.getDependencies().size() : 0);
    }

    /**
     * Converts a Maven model dependency to an Aether {@link Dependency}.
     *
     * <p>
     * For types with handler-provided classifiers (e.g. {@code test-jar},
     * {@code java-source}), the Maven type is mapped to the corresponding
     * Aether extension and classifier. For example, a POM dependency with
     * {@code <type>test-jar</type>} and no explicit classifier becomes
     * {@code extension="jar", classifier="tests"} in Aether.
     * </p>
     */
    private static Dependency toAetherDependency(org.apache.maven.model.Dependency dep) {
        return new Dependency(
                SbomUtils.toAetherArtifact(dep.getGroupId(), dep.getArtifactId(),
                        dep.getVersion(), dep.getType(), dep.getClassifier()),
                dep.getScope());
    }

    private static final Set<String> KNOWN_ARCHIVE_TYPES = Set.of(
            "zip", "jar", "war", "ear", "rar", "tar", "gz", "bz2", "xz", "zst",
            "tar.gz", "tar.bz2", "tar.xz", "tar.zst");

    /**
     * Derives the archive type from the destination filename.
     *
     * <p>
     * Returns {@code null} for directory-based assemblies where the
     * filename has no recognized archive extension.
     * </p>
     */
    private static String detectArchiveType(Archiver archiver) {
        File destFile = archiver.getDestFile();
        if (destFile == null) {
            return null;
        }
        String name = destFile.getName();
        for (String compound : new String[] { ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst" }) {
            if (name.endsWith(compound)) {
                return compound.substring(1);
            }
        }
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            String ext = name.substring(dot + 1);
            if (KNOWN_ARCHIVE_TYPES.contains(ext)) {
                return ext;
            }
        }
        return null;
    }

    private boolean isEmbedded() {
        return "embedded".equalsIgnoreCase(output) || "all".equalsIgnoreCase(output);
    }

    private boolean isExternal() {
        return "external".equalsIgnoreCase(output) || "all".equalsIgnoreCase(output);
    }

    /** No-op — this handler does not process archive extraction. */
    @Override
    public void finalizeArchiveExtraction(UnArchiver unarchiver) {
    }

    @Override
    public List<String> getVirtualFiles() {
        if (!isEmbedded()) {
            return List.of();
        }
        return List.of(outputPath);
    }

    /** Sets the output format ({@code "json"} or {@code "xml"}). */
    @SuppressWarnings("unused")
    public void setFormat(String format) {
        this.format = format;
    }

    /** Sets the output filename within the archive. */
    @SuppressWarnings("unused")
    public void setOutputPath(String outputPath) {
        this.outputPath = outputPath;
    }

    /** Enables indented output for readability (JSON only). */
    @SuppressWarnings("unused")
    public void setPrettyPrint(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    /**
     * Sets the output mode: {@code "embedded"} (inside the archive),
     * {@code "external"} (next to the archive), or {@code "all"} (both).
     */
    @SuppressWarnings("unused")
    public void setOutput(String output) {
        this.output = output;
    }

    /** Sets the hash algorithm for content hashes. */
    @SuppressWarnings("unused")
    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    /** Controls whether missing license info causes a build failure. */
    @SuppressWarnings("unused")
    public void setFailOnMissingLicense(boolean failOnMissingLicense) {
        this.failOnMissingLicense = failOnMissingLicense;
    }

    /** Controls whether duplicate artifact hashes cause a build failure. */
    @SuppressWarnings("unused")
    public void setFailOnDuplicateHash(boolean failOnDuplicateHash) {
        this.failOnDuplicateHash = failOnDuplicateHash;
    }
}
