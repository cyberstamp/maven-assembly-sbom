package io.github.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugins.assembly.filter.ContainerDescriptorHandler;
import org.apache.maven.plugins.assembly.model.Assembly;
import org.apache.maven.plugins.assembly.model.io.xpp3.AssemblyXpp3Reader;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.codehaus.plexus.archiver.ArchiveEntry;
import org.codehaus.plexus.archiver.Archiver;
import org.codehaus.plexus.archiver.ArchiverException;
import org.codehaus.plexus.archiver.ResourceIterator;
import org.codehaus.plexus.archiver.UnArchiver;
import org.codehaus.plexus.components.io.fileselectors.FileInfo;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Hash;
import org.eclipse.aether.RepositorySystem;
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

    @Inject
    private MavenProjectHelper projectHelper;

    private String format = "json";
    private String outputPath = "bom.cdx.json";
    private String outputMode = "embedded";
    private String hashAlgorithm = "SHA-256";
    private boolean prettyPrint;
    private boolean failOnMissingLicense;
    private boolean failOnDuplicateHash = true;
    private String embeddedSboms = "merge";
    private String externalSboms;
    private boolean librariesOnly;
    private boolean attach;
    private ProductInfo product;

    private boolean includeBaseDir;
    private String assemblyId;
    private String classifier;
    private boolean doAttach;
    // not thread-safe — safe here because finalizeArchiveCreation is single-threaded
    private MessageDigest messageDigest;
    private Hash.Algorithm bomHashAlgorithm;
    private String outputArchivePath;

    /**
     * Filters out embedded SBOM files and their parent directories from
     * unpacked archives when {@code embeddedSboms} is set to
     * {@code "merge"}, since their contents are merged into the
     * distribution's own SBOM. The handler's own output entry is
     * identified by its exact archive path and passes through.
     */
    @Override
    public boolean isSelected(FileInfo fileInfo) throws IOException {
        if ("merge".equalsIgnoreCase(embeddedSboms)
                && fileInfo.getName() != null) {
            String name = fileInfo.getName();
            if (outputArchivePath != null && name.equals(outputArchivePath)) {
                return true;
            }
            if (BomReader.isSbomFile(name) || isSbomDirectory(name)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSbomDirectory(String path) {
        return path.endsWith("/META-INF/sbom")
                || path.endsWith("/META-INF/sbom/")
                || path.equals("META-INF/sbom")
                || path.equals("META-INF/sbom/");
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

            List<Bom> externalBomList = SbomGenerator.parseExternalBoms(
                    externalSboms,
                    project.getBasedir() != null ? project.getBasedir().toPath() : null);

            List<ArchiveContent.FileEntry> entries = collectArchiveEntries(archiver);
            String baseDirPrefix = detectBaseDirPrefix(entries);

            SbomGenerator generator = new SbomGenerator(
                    project, session, repoSystem, effectiveModelResolver,
                    messageDigest, bomHashAlgorithm,
                    failOnDuplicateHash, failOnMissingLicense, embeddedSboms,
                    librariesOnly);
            generator.setProduct(product);
            Bom bom = generator.generate(entries, baseDirPrefix, externalBomList,
                    assemblyId, classifier, detectArchiveType(archiver));

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

    /**
     * Initializes per-archive configuration.
     *
     * <p>
     * Validates the configured format, output mode, embedded SBOM
     * handling, hash algorithm, and attachment settings. Resolves the
     * assembly descriptor to determine the classifier, base-directory
     * inclusion, and whether the distribution archive is attached.
     * </p>
     *
     * @throws ArchiverException if any configuration value is invalid
     */
    private void initConfig(Archiver archiver) throws ArchiverException {
        if (!"json".equalsIgnoreCase(format) && !"xml".equalsIgnoreCase(format)) {
            throw new ArchiverException(
                    "Unsupported SBOM format: " + format + ". Supported values: json, xml");
        }
        if (!isEmbedded() && !isExternal()) {
            throw new ArchiverException(
                    "Unsupported output mode: " + outputMode
                            + ". Supported values: embedded, external, all");
        }
        if (attach && !isExternal()) {
            throw new ArchiverException(
                    "SBOM attach requires outputMode 'external' or 'all', "
                            + "but outputMode is '" + outputMode + "'");
        }
        if (!"merge".equalsIgnoreCase(embeddedSboms)
                && !"link".equalsIgnoreCase(embeddedSboms)
                && !"ignore".equalsIgnoreCase(embeddedSboms)) {
            throw new ArchiverException(
                    "Unsupported embeddedSboms: " + embeddedSboms
                            + ". Supported values: merge, link, ignore");
        }
        AssemblyConfig assemblyConfig = resolveAssemblyConfig(archiver);
        includeBaseDir = assemblyConfig.assembly == null
                || assemblyConfig.assembly.isIncludeBaseDirectory();
        assemblyId = assemblyConfig.assembly != null
                ? assemblyConfig.assembly.getId()
                : "assembly";
        classifier = assemblyConfig.classifier;
        doAttach = resolveDoAttach(assemblyConfig);
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
     * Determines whether the SBOM should actually be attached to the
     * Maven project, considering both this handler's {@code attach}
     * setting and whether the Maven Assembly Plugin attaches the
     * distribution archive itself.
     *
     * <p>
     * If {@code attach} is {@code true} but the assembly plugin does
     * not attach the archive (its own {@code attach} is {@code false}),
     * a warning is logged and attachment is skipped.
     * </p>
     *
     * @param assemblyConfig the resolved assembly configuration
     * @return {@code true} if the SBOM should be attached
     */
    private boolean resolveDoAttach(AssemblyConfig assemblyConfig) {
        if (!attach) {
            return false;
        }
        if (!assemblyConfig.assemblyAttach) {
            log.warn("SBOM attach is enabled but the Maven Assembly Plugin "
                    + "does not attach the distribution archive; "
                    + "skipping SBOM attachment");
            return false;
        }
        return true;
    }

    /**
     * Iterates all file entries in the archiver and computes their hashes.
     */
    private List<ArchiveContent.FileEntry> collectArchiveEntries(Archiver archiver)
            throws IOException {
        boolean filterSboms = "merge".equalsIgnoreCase(embeddedSboms);
        List<ArchiveContent.FileEntry> entries = new ArrayList<>();
        for (ResourceIterator it = archiver.getResources(); it.hasNext();) {
            ArchiveEntry ae = it.next();
            if (ae.getType() != ArchiveEntry.FILE) {
                continue;
            }
            if (filterSboms && BomReader.isSbomFile(ae.getName())) {
                continue;
            }
            try (InputStream is = ae.getInputStream()) {
                entries.add(new ArchiveContent.FileEntry(ae.getName(),
                        SbomUtils.computeHash(messageDigest, is), ae.getFile()));
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
     * Resolved assembly descriptor configuration.
     *
     * @param assembly the parsed assembly descriptor, or {@code null}
     *        if it could not be located
     * @param classifier the artifact classifier derived from the
     *        assembly plugin configuration (may be {@code null})
     * @param assemblyAttach whether the Maven Assembly Plugin attaches
     *        the archive as a project artifact
     */
    private record AssemblyConfig(Assembly assembly, String classifier,
            boolean assemblyAttach) {
    }

    /**
     * Locates the assembly descriptor that produced the archive and
     * resolves the artifact classifier and attachment setting from the
     * plugin configuration.
     *
     * <p>
     * The classifier is determined by the assembly plugin's
     * {@code appendAssemblyId} and {@code classifier} settings:
     * if an explicit {@code classifier} is configured, it is used;
     * otherwise, the assembly id is used as the classifier unless
     * {@code appendAssemblyId} is set to {@code false}.
     * </p>
     *
     * <p>
     * The {@code assemblyAttach} flag reflects the assembly plugin's
     * own {@code attach} configuration (default {@code true}). When
     * the assembly plugin does not attach the archive to the project,
     * the SBOM should not be attached either.
     * </p>
     */
    private AssemblyConfig resolveAssemblyConfig(Archiver archiver) {
        try {
            File destFile = archiver.getDestFile();
            if (destFile == null) {
                return new AssemblyConfig(null, null, true);
            }
            String destName = destFile.getName();
            org.apache.maven.model.PluginExecution soleExec = null;
            Assembly soleAssembly = null;
            boolean solePluginAttach = true;
            boolean foundPlugin = false;
            int candidateCount = 0;
            for (org.apache.maven.model.Plugin plugin : project.getBuild().getPlugins()) {
                if (!"maven-assembly-plugin".equals(plugin.getArtifactId())) {
                    continue;
                }
                foundPlugin = true;
                boolean pluginAttach = resolveAssemblyAttach(plugin.getConfiguration());
                solePluginAttach = pluginAttach;
                String defaultFinalName = resolveFinalName(plugin.getConfiguration());
                for (org.apache.maven.model.PluginExecution exec : plugin.getExecutions()) {
                    boolean execAttach = resolveAssemblyAttach(
                            exec.getConfiguration(), pluginAttach);
                    List<Assembly> descriptors = findAllDescriptors(exec);
                    Assembly match = matchDescriptorByFilename(
                            exec, destName, defaultFinalName, descriptors);
                    if (match != null) {
                        String classifier = resolveClassifier(exec, match.getId());
                        return new AssemblyConfig(match, classifier, execAttach);
                    }
                    for (Assembly candidate : descriptors) {
                        candidateCount++;
                        soleExec = exec;
                        soleAssembly = candidate;
                        solePluginAttach = pluginAttach;
                    }
                }
            }
            if (candidateCount == 1) {
                String classifier = resolveClassifier(soleExec, soleAssembly.getId());
                boolean soleAttach = resolveAssemblyAttach(
                        soleExec.getConfiguration(), solePluginAttach);
                return new AssemblyConfig(soleAssembly, classifier, soleAttach);
            }
            if (foundPlugin) {
                return new AssemblyConfig(null, null, solePluginAttach);
            }
        } catch (Exception e) {
            log.debug("Could not locate assembly descriptor for {}", archiver.getDestFile(), e);
        }
        return new AssemblyConfig(null, null, true);
    }

    /**
     * Resolves the assembly plugin's {@code attach} setting from a
     * configuration element.
     *
     * @param config the plugin or execution configuration (may be {@code null})
     * @return {@code true} if the archive should be attached (the default)
     */
    private static boolean resolveAssemblyAttach(Object config) {
        return resolveAssemblyAttach(config, true);
    }

    /**
     * Resolves the assembly plugin's {@code attach} setting from a
     * configuration element, falling back to the given default.
     *
     * @param config the plugin or execution configuration (may be {@code null})
     * @param fallback the value to return if no {@code attach} element is present
     * @return {@code true} if the archive should be attached
     */
    private static boolean resolveAssemblyAttach(Object config, boolean fallback) {
        String value = getConfigValue(config, "attach");
        if (value == null) {
            return fallback;
        }
        return !"false".equalsIgnoreCase(value);
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
     * Writes the BOM as an external file, embedded in the archive, or
     * both, depending on the configured {@code outputMode}. When
     * {@link #doAttach} is {@code true}, the external BOM file is
     * registered as an attached Maven project artifact.
     *
     * <p>
     * Attachment is deferred to a post-archive hook so that the
     * attached file includes the archive's content hash. If the hook
     * cannot be registered, attachment falls back to this method and
     * the BOM will not contain the archive hash.
     * </p>
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
            boolean hookRegistered = registerPostArchiveHook(
                    archiver, bom, externalBomPath, tempFile);
            if (doAttach && externalBomPath != null && !hookRegistered) {
                attachSbomArtifact(externalBomPath, resolveAttachType(), classifier);
            }
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
     * Registers a single post-archive closeable that updates the
     * external BOM with the archive hash, attaches the SBOM artifact
     * if configured, and deletes the embedded BOM temp file.
     *
     * <p>
     * The Plexus Archiver API provides no public post-write hook.
     * This method accesses the internal {@code closeables} list via
     * reflection as a best-effort mechanism. If the field is missing
     * or inaccessible, a warning is logged and the BOM is
     * produced without the archive hash.
     * </p>
     *
     * @return {@code true} if the hook was successfully registered
     */
    @SuppressWarnings("unchecked")
    private boolean registerPostArchiveHook(Archiver archiver, Bom bom,
            Path externalBomPath, Path tempFile) {
        try {
            java.lang.reflect.Field field = findField(archiver.getClass(), "closeables");
            if (field == null) {
                if (externalBomPath != null) {
                    log.warn("Could not find closeables field on archiver, "
                            + "archive hash will not be added to the external BOM");
                }
                return false;
            }
            field.setAccessible(true);
            List<java.io.Closeable> closeables = (List<java.io.Closeable>) field.get(archiver);
            MessageDigest digest = messageDigest;
            Hash.Algorithm algorithm = bomHashAlgorithm;
            boolean attachInHook = doAttach;
            String attachType = resolveAttachType();
            String attachClassifier = classifier;
            closeables.add(() -> {
                if (externalBomPath != null) {
                    updateBomWithArchiveHash(archiver, bom, externalBomPath, digest, algorithm);
                }
                if (attachInHook && externalBomPath != null) {
                    attachSbomArtifact(externalBomPath, attachType, attachClassifier);
                }
                if (tempFile != null) {
                    Files.deleteIfExists(tempFile);
                }
            });
            return true;
        } catch (Exception e) {
            if (externalBomPath != null) {
                log.warn("Could not register post-archive hook, "
                        + "archive hash will not be added to the external BOM", e);
            }
            return false;
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
     * Returns the Maven artifact type for the SBOM attachment.
     */
    private String resolveAttachType() {
        return "xml".equalsIgnoreCase(format) ? "cdx.xml" : "cdx.json";
    }

    /**
     * Attaches the SBOM file as a Maven project artifact that mirrors
     * the distribution archive's coordinates with the given type.
     */
    private void attachSbomArtifact(Path bomFile, String type, String classifier) {
        projectHelper.attachArtifact(project, type, classifier, bomFile.toFile());
        log.info("Attached SBOM artifact: type={}, classifier={}", type, classifier);
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
        outputArchivePath = baseDirPrefix != null
                ? baseDirPrefix + outputPath
                : outputPath;
        archiver.addFile(tempFile.toFile(), outputArchivePath);
        return tempFile;
    }

    /**
     * Serializes the BOM in the configured format.
     */
    private void writeBom(Bom bom, Path output)
            throws IOException, org.cyclonedx.exception.GeneratorException {
        BomWriter.write(bom, output, format, prettyPrint);
    }

    /**
     * Logs a summary of the generated BOM.
     */
    private void logBomSummary(Bom bom) {
        List<org.cyclonedx.model.Component> components = bom.getComponents();
        if (components == null) {
            log.debug("SBOM: 0 components, {} dependency entries",
                    bom.getDependencies() != null ? bom.getDependencies().size() : 0);
            return;
        }
        long libCount = components.stream()
                .filter(c -> c.getType() == org.cyclonedx.model.Component.Type.LIBRARY).count();
        long fileCount = components.size() - libCount;
        log.debug("SBOM: {} libraries, {} files, {} dependency entries",
                libCount, fileCount,
                bom.getDependencies() != null ? bom.getDependencies().size() : 0);
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
        return "embedded".equalsIgnoreCase(outputMode) || "all".equalsIgnoreCase(outputMode);
    }

    private boolean isExternal() {
        return "external".equalsIgnoreCase(outputMode) || "all".equalsIgnoreCase(outputMode);
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
    public void setOutputMode(String outputMode) {
        this.outputMode = outputMode;
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

    /**
     * Sets how embedded CycloneDX SBOMs found in the archive are handled.
     *
     * <p>
     * Supported values:
     * </p>
     * <ul>
     * <li>{@code "merge"} (default) — merge the SBOM's components as
     * nested sub-components of the containing artifact. The physical
     * SBOM files and their {@code META-INF/sbom} directories are
     * excluded from the output archive since their contents are
     * incorporated into the distribution's own SBOM.</li>
     * <li>{@code "link"} — add an external reference of type {@code bom}
     * to the containing artifact</li>
     * <li>{@code "ignore"} — do not process embedded SBOMs</li>
     * </ul>
     */
    @SuppressWarnings("unused")
    public void setEmbeddedSboms(String embeddedSboms) {
        this.embeddedSboms = embeddedSboms;
    }

    /**
     * Sets the paths to external CycloneDX SBOM files to merge into
     * the distribution SBOM.
     *
     * <p>
     * Accepts a comma-separated list of file paths. Relative paths
     * are resolved against the project base directory. External SBOMs
     * are merged under the main distribution component and their
     * component hashes participate in archive entry matching.
     * </p>
     */
    @SuppressWarnings("unused")
    public void setExternalSboms(String externalSboms) {
        this.externalSboms = externalSboms;
    }

    /**
     * Excludes generic file components, keeping only libraries (Maven, npm, etc.).
     */
    @SuppressWarnings("unused")
    public void setLibrariesOnly(boolean librariesOnly) {
        this.librariesOnly = librariesOnly;
    }

    /**
     * Attaches the generated SBOM as a Maven project artifact.
     *
     * <p>
     * When enabled, the SBOM is registered as an attached artifact
     * with the same groupId, artifactId, classifier, and version as
     * the distribution archive but with a different type
     * ({@code cdx.json} or {@code cdx.xml} depending on the
     * configured {@linkplain #setFormat(String) format}).
     * </p>
     *
     * <p>
     * Requires {@linkplain #setOutputMode(String) outputMode} to
     * include external output ({@code "external"} or {@code "all"}).
     * If the Maven Assembly Plugin's own {@code attach} configuration
     * is {@code false} (i.e., the distribution archive is not
     * attached), the SBOM will not be attached either.
     * </p>
     */
    @SuppressWarnings("unused")
    public void setAttach(boolean attach) {
        this.attach = attach;
    }

    /**
     * Sets user-configurable metadata (CPE, description, supplier,
     * manufacturer, publisher, copyright) for the main BOM component.
     */
    @SuppressWarnings("unused")
    public void setProduct(ProductInfo product) {
        this.product = product;
    }
}
