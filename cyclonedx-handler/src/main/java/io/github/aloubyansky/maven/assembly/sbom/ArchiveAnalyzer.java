package io.github.aloubyansky.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Matches archive entries to Maven artifacts by content hash and
 * detects unpacked (exploded) archives within the assembly.
 *
 * <p>
 * This class encapsulates the artifact identification pipeline:
 * hash-based matching, unpacked artifact detection via ZIP content
 * scanning, and nested JAR identification via dependency resolution
 * or embedded {@code pom.properties}.
 * </p>
 */
class ArchiveAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ArchiveAnalyzer.class);
    public static final String JAR = "jar";
    private static final Set<String> ZIP_BASED_EXTENSIONS = Set.of(
            ".jar", ".war", ".ear", ".rar", ".par");

    private static final Comparator<String> JSON_FIRST_SBOM_ORDER = Comparator
            .<String, Boolean> comparing(p -> !p.endsWith(".cdx.json"))
            .thenComparing(Comparator.naturalOrder());

    private final EffectiveModelResolver effectiveModelResolver;
    private final RepositorySystem repoSystem;
    private final MavenProject project;
    private final MavenSession session;
    // not thread-safe — safe here because the matcher runs on a single thread
    private final MessageDigest messageDigest;
    private final boolean failOnDuplicateHash;
    private final Map<ArtifactCoords, MavenProject> reactorModuleIndex;
    private final List<Bom> externalBoms;
    private final boolean detectEmbeddedSboms;
    private List<Artifact> allArtifacts;
    private ArtifactHashIndex hashIndex;

    /**
     * Result of scanning a ZIP file's contents against unmatched
     * archive entries.
     *
     * @param matchedArchiveEntries archive entries matched by hash
     * @param hashToZipEntryNames content hash to ZIP entry name mapping
     */
    record ZipScanResult(Set<ArchiveContent.FileEntry> matchedArchiveEntries,
            Map<String, List<String>> hashToZipEntryNames) {

        /** Returns {@code true} if at least one entry matched. */
        boolean hasMatchedEntries() {
            return !matchedArchiveEntries.isEmpty();
        }

        /**
         * Derives the common unpack prefix from matched entries.
         *
         * @return the prefix (with trailing slash), or {@code null}
         */
        String computeUnpackPrefix() {
            String prefix = null;
            for (ArchiveContent.FileEntry entry : matchedArchiveEntries) {
                List<String> zipNames = hashToZipEntryNames.get(entry.hash());
                if (zipNames == null) {
                    continue;
                }
                String entryPrefix = null;
                for (String zipName : zipNames) {
                    if (entry.path().endsWith(zipName)) {
                        entryPrefix = entry.path().substring(
                                0, entry.path().length() - zipName.length());
                        break;
                    }
                }
                if (entryPrefix == null) {
                    continue;
                }
                if (prefix == null) {
                    prefix = entryPrefix;
                } else if (!prefix.equals(entryPrefix)) {
                    return null;
                }
            }
            return prefix;
        }
    }

    ArchiveAnalyzer(EffectiveModelResolver effectiveModelResolver,
            RepositorySystem repoSystem,
            MavenProject project,
            MavenSession session,
            MessageDigest messageDigest,
            boolean failOnDuplicateHash) {
        this(effectiveModelResolver, repoSystem, project, session,
                messageDigest, failOnDuplicateHash, List.of(), true);
    }

    ArchiveAnalyzer(EffectiveModelResolver effectiveModelResolver,
            RepositorySystem repoSystem,
            MavenProject project,
            MavenSession session,
            MessageDigest messageDigest,
            boolean failOnDuplicateHash,
            List<Bom> externalBoms,
            boolean detectEmbeddedSboms) {
        this.effectiveModelResolver = effectiveModelResolver;
        this.repoSystem = repoSystem;
        this.project = project;
        this.session = session;
        this.messageDigest = messageDigest;
        this.failOnDuplicateHash = failOnDuplicateHash;
        this.reactorModuleIndex = indexReactorModules(session.getProjects());
        this.externalBoms = externalBoms;
        this.detectEmbeddedSboms = detectEmbeddedSboms;
    }

    /**
     * Indexes reactor projects by artifact id for O(1) lookup.
     */
    private static Map<ArtifactCoords, MavenProject> indexReactorModules(
            List<MavenProject> projects) {
        Map<ArtifactCoords, MavenProject> index = new HashMap<>(projects.size());
        for (MavenProject p : projects) {
            index.put(ArtifactCoords.of(p), p);
        }
        return index;
    }

    /**
     * Returns the project's resolved dependencies plus its own artifact,
     * collecting them on first access.
     */
    private List<Artifact> allArtifacts() {
        if (allArtifacts == null) {
            allArtifacts = new ArrayList<>();
            if (project.getArtifacts() != null) {
                allArtifacts.addAll(project.getArtifacts());
            }
            Artifact projectArtifact = project.getArtifact();
            if (projectArtifact != null && projectArtifact.getFile() != null) {
                allArtifacts.add(projectArtifact);
            }
        }
        return allArtifacts;
    }

    /**
     * Analyzes archive entries against Maven artifacts and returns
     * classified results.
     *
     * @param entries the archive file entries with content hashes
     * @param baseDirPrefix the base directory prefix to strip, or {@code null}
     * @return the classified assembly content
     * @throws IllegalStateException if duplicate hashes are detected
     *         and the matcher is configured to fail on duplicates
     */
    ArchiveContent analyze(List<ArchiveContent.FileEntry> entries, String baseDirPrefix) {
        ArchiveContent content = new ArchiveContent();
        Set<Artifact> matchedArtifacts = new HashSet<>();
        Map<String, ArchiveContent.FileEntry> unmatchedByPath = new HashMap<>();

        classifyArchiveEntries(entries, baseDirPrefix, content,
                matchedArtifacts, unmatchedByPath);
        if (!unmatchedByPath.isEmpty()) {
            detectUnpackedArtifacts(matchedArtifacts, unmatchedByPath, content);
            reclassifyEntriesUnderUnpackedArtifacts(content);
        }
        if (!unmatchedByPath.isEmpty()) {
            detectMavenMetadataInUnmatchedJars(unmatchedByPath, content);
        }
        if (!unmatchedByPath.isEmpty()) {
            matchAgainstExternalSboms(unmatchedByPath, content);
        }
        if (detectEmbeddedSboms) {
            Set<String> detectedSbomPaths = new HashSet<>();
            detectSbomsInArtifactJars(content, detectedSbomPaths);
            detectedSbomPaths.forEach(unmatchedByPath::remove);
        }

        for (ArchiveContent.FileEntry entry : unmatchedByPath.values()) {
            content.addUnmatchedFile(entry);
        }

        return content;
    }

    /**
     * Classifies archive entries as matched or unmatched by hash lookup.
     */
    private void classifyArchiveEntries(List<ArchiveContent.FileEntry> entries,
            String baseDirPrefix,
            ArchiveContent content,
            Set<Artifact> matchedArtifacts,
            Map<String, ArchiveContent.FileEntry> unmatchedByPath) {
        hashIndex = new ArtifactHashIndex(allArtifacts(), messageDigest, failOnDuplicateHash);
        for (ArchiveContent.FileEntry entry : entries) {
            String relativePath = stripBaseDir(entry.path(), baseDirPrefix);
            if (relativePath.isEmpty()) {
                continue;
            }
            List<Artifact> artifacts = hashIndex.lookup(entry.hash());
            if (artifacts != null) {
                for (Artifact artifact : artifacts) {
                    matchedArtifacts.add(artifact);
                    content.addMavenEntry(new ArchiveContent.MavenEntry(
                            ArtifactCoords.of(artifact), relativePath, entry.hash()));
                    detectBundledDepsInArtifactFile(artifact, content);
                }
            } else {
                unmatchedByPath.put(relativePath,
                        new ArchiveContent.FileEntry(relativePath, entry.hash(), entry.sourceFile()));
            }
        }
    }

    /**
     * Detects artifacts that were unpacked into the assembly.
     * Matched entries are removed from {@code unmatchedByPath}.
     */
    private void detectUnpackedArtifacts(
            Set<Artifact> matchedArtifacts,
            Map<String, ArchiveContent.FileEntry> unmatchedByPath,
            ArchiveContent content) {

        Map<String, List<ArchiveContent.FileEntry>> entriesByHash = indexEntriesByHash(unmatchedByPath.values());

        for (Artifact artifact : allArtifacts()) {
            if (entriesByHash.isEmpty()) {
                break;
            }
            if (matchedArtifacts.contains(artifact)) {
                continue;
            }
            if (artifact.getFile() == null || !artifact.getFile().isFile()) {
                continue;
            }
            tryMatchUnpackedArtifact(artifact, entriesByHash,
                    matchedArtifacts, unmatchedByPath, content);
        }
    }

    /**
     * Reclassifies top-level {@link ArchiveContent.MavenEntry} records
     * whose paths fall inside a detected unpacked artifact. An unpacked
     * artifact is recognized by its {@code archivePath} ending with
     * {@code '/'}. Root-level overlays (empty archivePath) are skipped
     * to avoid reclassifying independent top-level entries. When
     * multiple prefixes match, the longest prefix wins to correctly
     * handle nested unpacked archives.
     *
     * <p>
     * Entries that belong to an unpacked artifact are removed from the
     * top-level list and added as {@link ArchiveContent.NestedMavenEntry}
     * records under the unpacked parent.
     * </p>
     */
    private static void reclassifyEntriesUnderUnpackedArtifacts(ArchiveContent content) {
        // collect unpacked artifact prefixes → parent coords
        Map<String, ArtifactCoords> prefixToParent = null;
        for (ArchiveContent.MavenEntry entry : content.mavenEntries()) {
            String path = entry.archivePath();
            if (path != null && path.endsWith("/")) {
                if (prefixToParent == null) {
                    prefixToParent = new HashMap<>();
                }
                prefixToParent.put(path, entry.artifactId());
            }
        }
        if (prefixToParent == null) {
            return;
        }

        var it = content.mavenEntries().iterator();
        while (it.hasNext()) {
            ArchiveContent.MavenEntry entry = it.next();
            String path = entry.archivePath();
            if (path == null || path.endsWith("/") || path.isEmpty()) {
                continue;
            }
            // match the longest prefix to handle nested unpacked archives
            String longestPrefix = null;
            for (String pfx : prefixToParent.keySet()) {
                if (path.startsWith(pfx)
                        && (longestPrefix == null || pfx.length() > longestPrefix.length())) {
                    longestPrefix = pfx;
                }
            }
            if (longestPrefix != null) {
                ArtifactCoords parentId = prefixToParent.get(longestPrefix);
                if (!parentId.equals(entry.artifactId())) {
                    it.remove();
                    content.addNestedEntry(new ArchiveContent.NestedMavenEntry(
                            parentId, entry.artifactId(),
                            entry.archivePath(), entry.hash()));
                }
            }
        }
    }

    /**
     * Indexes entries by content hash.
     */
    private static Map<String, List<ArchiveContent.FileEntry>> indexEntriesByHash(
            Iterable<ArchiveContent.FileEntry> entries) {
        Map<String, List<ArchiveContent.FileEntry>> index = new HashMap<>();
        for (ArchiveContent.FileEntry e : entries) {
            if (e.hash() != null) {
                index.computeIfAbsent(e.hash(), k -> new ArrayList<>(1)).add(e);
            }
        }
        return index;
    }

    /**
     * Scans unmatched JAR entries for embedded {@code pom.properties}
     * to identify non-dependency JARs as Maven components.
     * Identified entries are removed from {@code unmatchedByPath}.
     */
    private static void detectMavenMetadataInUnmatchedJars(
            Map<String, ArchiveContent.FileEntry> unmatchedByPath,
            ArchiveContent content) {
        List<ArchiveContent.FileNestedArtifact> fileNestedArtifacts = content.fileNestedArtifacts();
        Set<String> alreadyProcessed = new HashSet<>(fileNestedArtifacts.size());
        for (ArchiveContent.FileNestedArtifact fna : fileNestedArtifacts) {
            alreadyProcessed.add(fna.filePath());
        }
        var it = unmatchedByPath.values().iterator();
        while (it.hasNext()) {
            ArchiveContent.FileEntry fileEntry = it.next();
            if (fileEntry.sourceFile() == null
                    || !fileEntry.sourceFile().isFile()
                    || !hasZipBasedExtension(fileEntry.path())
                    || alreadyProcessed.contains(fileEntry.path())) {
                continue;
            }
            try (ZipFile zf = new ZipFile(fileEntry.sourceFile())) {
                List<Properties> allProps = readPomPropertiesFromZip(zf);
                if (allProps.isEmpty()) {
                    continue;
                }
                boolean identified = allProps.size() == 1
                        ? registerFromStandaloneProps(allProps.get(0), fileEntry, content) != null
                        : registerStandaloneShadedJar(allProps, fileEntry, content);
                if (identified) {
                    it.remove();
                }
            } catch (IOException e) {
                log.debug("Could not read {} for Maven metadata", fileEntry.sourceFile(), e);
            }
        }
    }

    /**
     * Registers a standalone JAR as a Maven entry from pom.properties.
     *
     * @return the registered artifact coordinates, or {@code null} if
     *         required properties are missing
     */
    private static ArtifactCoords registerFromStandaloneProps(Properties props,
            ArchiveContent.FileEntry fileEntry, ArchiveContent content) {
        String gId = props.getProperty("groupId");
        String aId = props.getProperty("artifactId");
        String ver = props.getProperty("version");
        if (gId == null || aId == null || ver == null) {
            return null;
        }
        ArtifactCoords coords = ArtifactCoords.of(gId, aId, ver);
        content.addMavenEntry(new ArchiveContent.MavenEntry(
                coords, fileEntry.path(), fileEntry.hash()));
        return coords;
    }

    /**
     * Handles a standalone shaded JAR (multiple pom.properties, not a
     * known project dependency). Uses filename matching to determine
     * the owner, same logic as nested shaded JARs.
     *
     * @return {@code true} if the owner was identified and registered
     */
    private static boolean registerStandaloneShadedJar(List<Properties> allProps,
            ArchiveContent.FileEntry fileEntry, ArchiveContent content) {
        return resolveAndRegisterShadedOwner(allProps, fileEntry, content,
                fileEntry.path(),
                props -> registerFromStandaloneProps(props, fileEntry, content));
    }

    /**
     * Shared resolve/register/fallback flow for shaded JARs with multiple
     * pom.properties. Resolves the owner by filename, delegates registration
     * to the caller-provided function, and falls back to file-nested
     * recording on failure.
     *
     * @param registerOwner registers the owner and returns its coords, or null on failure
     * @return {@code true} if the owner was identified and registered
     */
    private static boolean resolveAndRegisterShadedOwner(
            List<Properties> allProps, ArchiveContent.FileEntry archiveEntry,
            ArchiveContent content, String pathForFilename,
            Function<Properties, ArtifactCoords> registerOwner) {
        Properties owner = resolveOwnerByFilename(allProps,
                SbomUtils.extractFileName(pathForFilename));
        if (owner == null) {
            log.debug("Could not determine owner of shaded JAR {},"
                    + " nesting all under file", pathForFilename);
            recordAllAsFileNested(archiveEntry, allProps, content);
            return false;
        }
        ArtifactCoords ownerCoords = registerOwner.apply(owner);
        if (ownerCoords == null) {
            recordAllAsFileNested(archiveEntry, allProps, content);
            return false;
        }
        registerBundledDependencies(ownerCoords, allProps, content);
        return true;
    }

    /**
     * Strips the base directory prefix from an archive path.
     */
    private static String stripBaseDir(String archivePath, String baseDirPrefix) {
        if (baseDirPrefix != null && archivePath.startsWith(baseDirPrefix)) {
            return archivePath.substring(baseDirPrefix.length());
        }
        return archivePath;
    }

    private static boolean hasZipBasedExtension(String path) {
        int dot = path.lastIndexOf('.');
        return dot >= 0 && ZIP_BASED_EXTENSIONS.contains(path.substring(dot));
    }

    /**
     * Attempts to match a single artifact as an unpacked archive.
     * Entries that match the archive content but cannot be positively
     * identified are preserved in {@code unmatchedByPath} so they
     * appear as file components in the final BOM. When pom.properties
     * are found inside an unidentified entry, the discovered artifacts
     * are recorded as file-nested entries.
     */
    private void tryMatchUnpackedArtifact(Artifact artifact,
            Map<String, List<ArchiveContent.FileEntry>> entriesByHash,
            Set<Artifact> matchedArtifacts,
            Map<String, ArchiveContent.FileEntry> unmatchedByPath,
            ArchiveContent content) {
        try (ZipFile zf = new ZipFile(artifact.getFile())) {
            ZipScanResult scan = scanZipForMatches(zf, entriesByHash);
            if (!scan.hasMatchedEntries()) {
                return;
            }

            matchedArtifacts.add(artifact);
            String occurrence = scan.computeUnpackPrefix();
            if (occurrence == null) {
                log.debug("Could not determine unpack prefix for {}", artifact);
            }
            content.addMavenEntry(new ArchiveContent.MavenEntry(
                    ArtifactCoords.of(artifact), occurrence, hashIndex.hashOf(artifact)));

            Map<String, Artifact> nestedArtifactsByHash = buildNestedArtifactHashMap(artifact);
            ArtifactCoords parentCoords = ArtifactCoords.of(artifact);

            for (ArchiveContent.FileEntry archiveEntry : scan.matchedArchiveEntries) {
                boolean identified = identifyNestedArtifact(archiveEntry, zf,
                        scan.hashToZipEntryNames, nestedArtifactsByHash,
                        parentCoords, matchedArtifacts, content);
                if (identified) {
                    unmatchedByPath.remove(archiveEntry.path());
                }
                entriesByHash.remove(archiveEntry.hash());
            }
        } catch (IOException e) {
            log.debug("Could not read {} as ZIP, skipping unpacked detection",
                    artifact.getFile(), e);
        }
    }

    /**
     * Scans ZIP entries and matches hashes against unmatched archive entries.
     */
    private ZipScanResult scanZipForMatches(ZipFile zf,
            Map<String, List<ArchiveContent.FileEntry>> entriesByHash)
            throws IOException {
        Set<ArchiveContent.FileEntry> matchedArchiveEntries = new HashSet<>();
        Map<String, List<String>> hashToZipEntryNames = new HashMap<>();

        Enumeration<? extends ZipEntry> zipEntries = zf.entries();
        while (zipEntries.hasMoreElements()) {
            ZipEntry ze = zipEntries.nextElement();
            if (ze.isDirectory()) {
                continue;
            }
            String hash;
            try (InputStream entryStream = zf.getInputStream(ze)) {
                hash = SbomUtils.computeHash(messageDigest, entryStream);
            }
            hashToZipEntryNames.computeIfAbsent(hash, k -> new ArrayList<>(1))
                    .add(ze.getName());
            List<ArchiveContent.FileEntry> matching = entriesByHash.get(hash);
            if (matching != null) {
                matchedArchiveEntries.addAll(matching);
            }
        }
        return new ZipScanResult(matchedArchiveEntries, hashToZipEntryNames);
    }

    /**
     * Identifies a nested artifact via hash lookup or pom.properties fallback.
     *
     * @return {@code true} if the artifact was positively identified
     */
    private boolean identifyNestedArtifact(ArchiveContent.FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            Map<String, Artifact> nestedArtifactsByHash,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        if (archiveEntry.hash() != null) {
            Artifact nestedArtifact = nestedArtifactsByHash.get(archiveEntry.hash());
            if (nestedArtifact != null) {
                registerNestedArtifact(nestedArtifact, archiveEntry, parentId, matchedArtifacts, content);
                detectBundledDependencies(archiveEntry, parentZip, hashToZipEntryNames,
                        ArtifactCoords.of(nestedArtifact), content);
                return true;
            }
        }
        return tryIdentifyFromPomProperties(archiveEntry, parentZip,
                hashToZipEntryNames, parentId, matchedArtifacts, content);
    }

    /**
     * Scans an artifact's JAR file directly for bundled (shaded) dependencies.
     */
    private void detectBundledDepsInArtifactFile(Artifact artifact, ArchiveContent content) {
        File file = artifact.getFile();
        if (file == null || !file.isFile()) {
            return;
        }
        try (ZipFile zf = new ZipFile(file)) {
            List<Properties> allProps = readPomPropertiesFromZip(zf);
            registerBundledDependencies(ArtifactCoords.of(artifact), allProps, content);
        } catch (IOException e) {
            log.debug("Could not scan {} for bundled dependencies", file, e);
        }
    }

    /**
     * Scans a hash-identified nested JAR for bundled (shaded) dependencies
     * by reading its pom.properties via the parent ZIP.
     */
    private void detectBundledDependencies(ArchiveContent.FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            ArtifactCoords ownerCoords, ArchiveContent content) {
        if (archiveEntry.hash() == null) {
            return;
        }
        List<String> zipEntryNames = hashToZipEntryNames.get(archiveEntry.hash());
        if (zipEntryNames == null) {
            return;
        }
        List<Properties> allProps = readAllPomProperties(parentZip, zipEntryNames.get(0));
        registerBundledDependencies(ownerCoords, allProps, content);
    }

    /**
     * Registers non-owner pom.properties entries as bundled nested components.
     */
    private static void registerBundledDependencies(ArtifactCoords ownerCoords, List<Properties> allProps,
            ArchiveContent content) {
        if (allProps.size() <= 1) {
            return;
        }
        for (Properties bp : allProps) {
            String gId = bp.getProperty("groupId");
            String aId = bp.getProperty("artifactId");
            String ver = bp.getProperty("version");
            if (gId != null && aId != null && ver != null
                    && !(gId.equals(ownerCoords.groupId())
                            && aId.equals(ownerCoords.artifactId())
                            && ver.equals(ownerCoords.version()))) {
                content.addNestedEntry(new ArchiveContent.NestedMavenEntry(
                        ownerCoords, ArtifactCoords.of(gId, aId, ver), null, null));
            }
        }
    }

    /**
     * Matches artifactIds from pom.properties entries against a JAR
     * filename to find the owner. Returns the single best match, or
     * {@code null} if the result is ambiguous (zero or multiple
     * equally-long matches).
     */
    private static Properties resolveOwnerByFilename(List<Properties> allProps,
            String fileName) {
        List<Properties> matching = new ArrayList<>();
        for (Properties p : allProps) {
            String aId = p.getProperty("artifactId");
            if (aId != null && fileName.contains(aId)) {
                matching.add(p);
            }
        }
        if (matching.size() > 1) {
            Properties best = null;
            int maxLen = 0;
            boolean unique = true;
            for (Properties p : matching) {
                int len = p.getProperty("artifactId").length();
                if (len > maxLen) {
                    maxLen = len;
                    best = p;
                    unique = true;
                } else if (len == maxLen) {
                    unique = false;
                }
            }
            return unique ? best : null;
        }
        return matching.size() == 1 ? matching.get(0) : null;
    }

    /**
     * Records all pom.properties entries as file-nested artifacts.
     */
    private static void recordAllAsFileNested(ArchiveContent.FileEntry archiveEntry, List<Properties> allProps,
            ArchiveContent content) {
        for (Properties p : allProps) {
            String gId = p.getProperty("groupId");
            String aId = p.getProperty("artifactId");
            String ver = p.getProperty("version");
            if (gId != null && aId != null && ver != null) {
                content.addFileNestedArtifact(archiveEntry.path(),
                        ArtifactCoords.of(gId, aId, ver));
            }
        }
    }

    /**
     * Reads all pom.properties entries directly from a ZIP file.
     */
    private static List<Properties> readPomPropertiesFromZip(ZipFile zf) throws IOException {
        List<Properties> result = new ArrayList<>();
        Enumeration<? extends ZipEntry> entries = zf.entries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            if (ze.getName().startsWith("META-INF/maven/")
                    && ze.getName().endsWith("/pom.properties")) {
                Properties props = new Properties();
                try (InputStream is = zf.getInputStream(ze)) {
                    props.load(is);
                }
                result.add(props);
            }
        }
        return result;
    }

    /**
     * Attempts to identify a nested JAR by reading embedded pom.properties.
     *
     * <p>
     * When a JAR contains multiple pom.properties (shaded/fat JAR), the
     * method attempts to match the JAR filename against the artifactIds.
     * If exactly one artifactId matches, that entry is used as the owner
     * and the remaining entries are registered as bundled nested components.
     * </p>
     *
     * @return {@code true} if the artifact was positively identified
     */
    private boolean tryIdentifyFromPomProperties(ArchiveContent.FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            ArtifactCoords parentId,
            Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        if (archiveEntry.hash() == null) {
            return false;
        }
        List<String> zipEntryNames = hashToZipEntryNames.get(archiveEntry.hash());
        if (zipEntryNames == null) {
            return false;
        }
        for (String zipEntryName : zipEntryNames) {
            List<Properties> allProps = readAllPomProperties(parentZip, zipEntryName);
            if (allProps.isEmpty()) {
                continue;
            }
            if (allProps.size() == 1) {
                return tryRegisterFromProps(allProps.get(0), archiveEntry,
                        parentId, matchedArtifacts, content) != null;
            }
            // Shaded JAR: match the filename against artifactIds
            return resolveAndRegisterShadedOwner(allProps, archiveEntry, content,
                    zipEntryName,
                    props -> tryRegisterFromProps(props, archiveEntry,
                            parentId, matchedArtifacts, content));
        }
        return false;
    }

    /**
     * Tries to register a nested artifact from the given pom.properties.
     *
     * @return the registered artifact's coordinates, or {@code null} if
     *         required properties are missing
     */
    private ArtifactCoords tryRegisterFromProps(Properties pomProps,
            ArchiveContent.FileEntry archiveEntry,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        String gId = pomProps.getProperty("groupId");
        String aId = pomProps.getProperty("artifactId");
        String ver = pomProps.getProperty("version");
        if (gId == null || aId == null || ver == null) {
            return null;
        }
        Artifact nested = new org.apache.maven.artifact.DefaultArtifact(
                gId, aId, ver, "compile", JAR, null,
                new org.apache.maven.artifact.handler.DefaultArtifactHandler(JAR));
        registerNestedArtifact(nested, archiveEntry, parentId, matchedArtifacts, content);
        return ArtifactCoords.of(nested);
    }

    /**
     * Records a nested artifact and its dependency relationship.
     */
    private void registerNestedArtifact(Artifact artifact, ArchiveContent.FileEntry archiveEntry,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        matchedArtifacts.add(artifact);
        ArtifactCoords nestedId = ArtifactCoords.of(artifact);
        content.addNestedEntry(new ArchiveContent.NestedMavenEntry(
                parentId, nestedId, archiveEntry.path(), archiveEntry.hash()));
        content.addDependencyEdge(parentId, nestedId);
        content.addNestedDependency(parentId, new Dependency(
                SbomUtils.toAetherArtifact(artifact.getGroupId(), artifact.getArtifactId(),
                        artifact.getVersion(), artifact.getType(), artifact.getClassifier()),
                "compile"));
    }

    /**
     * Reads all pom.properties entries from a nested JAR entry.
     */
    private static List<Properties> readAllPomProperties(ZipFile outerZip, String entryName) {
        ZipEntry entry = outerZip.getEntry(entryName);
        if (entry == null) {
            return List.of();
        }
        List<Properties> result = new ArrayList<>();
        try (InputStream is = outerZip.getInputStream(entry);
                ZipInputStream zis = new ZipInputStream(is)) {
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                if (ze.getName().startsWith("META-INF/maven/")
                        && ze.getName().endsWith("/pom.properties")) {
                    Properties props = new Properties();
                    props.load(zis);
                    result.add(props);
                }
            }
        } catch (IOException e) {
            log.debug("Failed to parse pom.properties from nested JAR {}", entryName, e);
        }
        return result;
    }

    /**
     * Builds a hash-to-artifact map for the given artifact's dependencies.
     */
    private Map<String, Artifact> buildNestedArtifactHashMap(Artifact artifact) {
        ArtifactCoords coords = ArtifactCoords.of(artifact);
        MavenProject module = reactorModuleIndex.get(coords);
        if (module != null && module.getArtifacts() != null) {
            return buildHashMapFromArtifacts(module.getArtifacts());
        }
        return buildHashMapFromEffectiveModel(artifact);
    }

    /**
     * Builds a hash-to-artifact map from pre-resolved Maven artifacts.
     */
    private Map<String, Artifact> buildHashMapFromArtifacts(Set<Artifact> artifacts) {
        Map<String, Artifact> map = new HashMap<>(artifacts.size());
        for (Artifact a : artifacts) {
            String hash = hashIndex.hashOf(a);
            if (hash != null) {
                map.put(hash, a);
            }
        }
        return map;
    }

    private static final Set<String> EXCLUDED_SCOPES = Set.of("test", "provided", "system");

    /**
     * Resolves dependencies from an artifact's effective POM and builds
     * a hash-to-artifact map. Only compile and runtime scoped dependencies
     * are included; test, provided, and system scopes are excluded.
     */
    private Map<String, Artifact> buildHashMapFromEffectiveModel(Artifact artifact) {
        Model model = effectiveModelResolver.resolveEffectiveModel(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());
        if (model == null || model.getDependencies() == null) {
            return Map.of();
        }

        Map<String, Artifact> map = new HashMap<>();
        for (org.apache.maven.model.Dependency dep : model.getDependencies()) {
            String scope = dep.getScope();
            if (scope == null || !EXCLUDED_SCOPES.contains(scope)) {
                resolveAndHashDependency(dep, map);
            }
        }
        return map;
    }

    /**
     * Resolves a single dependency's artifact and adds it to the hash map.
     */
    private void resolveAndHashDependency(org.apache.maven.model.Dependency dep,
            Map<String, Artifact> map) {
        try {
            org.eclipse.aether.artifact.DefaultArtifact aetherArtifact = SbomUtils.toAetherArtifact(
                    dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                    dep.getType(), dep.getClassifier());
            ArtifactRequest request = new ArtifactRequest(
                    aetherArtifact, project.getRemoteProjectRepositories(), null);
            ArtifactResult result = repoSystem.resolveArtifact(
                    session.getRepositorySession(), request);
            File file = result.getArtifact().getFile();
            if (file != null && file.isFile()) {
                Artifact mavenArtifact = new org.apache.maven.artifact.DefaultArtifact(
                        dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                        dep.getScope() != null ? dep.getScope() : "compile",
                        dep.getType() != null ? dep.getType() : JAR,
                        dep.getClassifier(),
                        new org.apache.maven.artifact.handler.DefaultArtifactHandler(
                                dep.getType() != null ? dep.getType() : JAR));
                mavenArtifact.setFile(file);
                String hash = hashIndex.hashOf(mavenArtifact);
                if (hash != null) {
                    map.put(hash, mavenArtifact);
                }
            }
        } catch (Exception e) {
            log.debug("Failed to resolve dependency {}:{}:{}",
                    dep.getGroupId(), dep.getArtifactId(), dep.getVersion(), e);
        }
    }

    // ---- External SBOM matching ----

    /**
     * Matches unmatched archive entries against components from external
     * SBOMs by content hash. Matched entries are removed from
     * {@code unmatchedByPath} and their archive path is recorded as
     * an {@link Occurrence} on the external component so the file
     * remains traceable in the final BOM.
     *
     * <p>
     * This enables non-Maven artifacts (e.g. npm packages) to be
     * identified when an external SBOM with matching hashes is provided.
     * Maven-identified artifacts take precedence — this method only
     * processes entries that were not matched by the Maven hash index.
     * </p>
     */
    private void matchAgainstExternalSboms(
            Map<String, ArchiveContent.FileEntry> unmatchedByPath,
            ArchiveContent content) {
        if (externalBoms.isEmpty()) {
            return;
        }
        Map<String, ExternalComponentRef> externalHashIndex = buildExternalHashIndex();
        if (externalHashIndex.isEmpty()) {
            return;
        }
        var it = unmatchedByPath.entrySet().iterator();
        while (it.hasNext()) {
            var entry = it.next();
            ExternalComponentRef ref = externalHashIndex.get(entry.getValue().hash());
            if (ref != null) {
                addOccurrence(ref.component(), entry.getKey());
                it.remove();
            }
        }
    }

    private static void addOccurrence(Component component, String archivePath) {
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
     * A component from an external SBOM paired with its source BOM.
     */
    private record ExternalComponentRef(Component component, Bom sourceBom) {
    }

    /**
     * Builds a hash-to-component index from all external SBOM components.
     *
     * <p>
     * Only components that declare content hashes using the configured
     * hash algorithm are indexed. Components without hashes are skipped.
     * </p>
     */
    private Map<String, ExternalComponentRef> buildExternalHashIndex() {
        Map<String, ExternalComponentRef> index = new HashMap<>();
        String targetAlg = messageDigest.getAlgorithm().replace("-", "")
                .toLowerCase();
        for (Bom bom : externalBoms) {
            if (bom.getComponents() == null) {
                continue;
            }
            indexComponentTree(bom.getComponents(), bom, targetAlg, index);
        }
        return index;
    }

    private static void indexComponentTree(List<Component> components, Bom bom,
            String targetAlg, Map<String, ExternalComponentRef> index) {
        for (Component comp : components) {
            String hash = extractMatchingHash(comp, targetAlg);
            if (hash != null) {
                index.putIfAbsent(hash, new ExternalComponentRef(comp, bom));
            }
            if (comp.getComponents() != null) {
                indexComponentTree(comp.getComponents(), bom, targetAlg, index);
            }
        }
    }

    /**
     * Extracts a hash value from a component that matches the target
     * algorithm. Returns {@code null} if no matching hash is found.
     */
    private static String extractMatchingHash(Component comp, String targetAlg) {
        if (comp.getHashes() == null) {
            return null;
        }
        for (Hash hash : comp.getHashes()) {
            if (hash.getAlgorithm() == null || hash.getValue() == null) {
                continue;
            }
            String algName = hash.getAlgorithm().replace("-", "")
                    .toLowerCase();
            if (targetAlg.equals(algName)) {
                return hash.getValue().toLowerCase();
            }
        }
        return null;
    }

    /**
     * Scans matched JAR/WAR artifacts for embedded CycloneDX SBOM files.
     *
     * <p>
     * For each Maven artifact that is a ZIP-based archive, scans its
     * entries for {@code .cdx.json} or {@code .cdx.xml} files. Detected
     * SBOMs are parsed and recorded in the content, with the artifact
     * as the parent.
     * </p>
     */
    private void detectSbomsInArtifactJars(ArchiveContent content,
            Set<String> detectedSbomPaths) {
        Map<ArtifactCoords, String> coordsToPath = new HashMap<>();
        for (ArchiveContent.MavenEntry entry : content.mavenEntries()) {
            coordsToPath.put(entry.artifactId(), entry.archivePath());
        }
        Set<ArtifactCoords> knownCoords = content.collectKnownArtifactCoords();
        Set<File> scannedFiles = new HashSet<>();
        for (Artifact artifact : allArtifacts()) {
            ArtifactCoords coords = ArtifactCoords.of(artifact);
            if (!knownCoords.contains(coords)) {
                continue;
            }
            File file = artifact.getFile();
            if (file == null || !file.isFile() || !hasZipBasedExtension(file.getName())) {
                continue;
            }
            if (!scannedFiles.add(file)) {
                continue;
            }
            String parentArchivePath = coordsToPath.get(coords);
            if (parentArchivePath == null) {
                parentArchivePath = "";
            }
            scanJarForSboms(file, coords, content,
                    parentArchivePath, detectedSbomPaths);
        }
    }

    /**
     * Scans a single JAR/WAR file for embedded SBOM entries.
     */
    private static void scanJarForSboms(File jarFile, ArtifactCoords artifactId,
            ArchiveContent content, String parentArchivePath,
            Set<String> detectedSbomPaths) {
        Set<String> processedStems = new HashSet<>();
        try (ZipFile zf = new ZipFile(jarFile)) {
            List<String> sbomEntryNames = new ArrayList<>();
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                if (!ze.isDirectory() && BomReader.isSbomFile(ze.getName())) {
                    sbomEntryNames.add(ze.getName());
                }
            }
            sbomEntryNames.sort(JSON_FIRST_SBOM_ORDER);
            for (String entryName : sbomEntryNames) {
                String stem = BomReader.sbomStem(entryName);
                if (!processedStems.add(stem)) {
                    continue;
                }
                try (InputStream is = zf.getInputStream(zf.getEntry(entryName))) {
                    Bom parsedBom = BomReader.readBom(is);
                    if (parsedBom != null) {
                        content.addDetectedSbom(new ArchiveContent.DetectedSbom(
                                entryName, parsedBom, artifactId));
                        detectedSbomPaths.add(
                                parentArchivePath + entryName);
                    }
                }
            }
        } catch (IOException e) {
            log.debug("Could not scan {} for embedded SBOMs", jarFile, e);
        }
    }
}
