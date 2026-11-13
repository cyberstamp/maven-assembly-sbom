package dev.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
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
    private final RemoteCoordinatesResolver remoteCoordinatesResolver;
    private boolean identityEvidence = true;
    private List<Artifact> allArtifacts;
    private ArtifactHashIndex hashIndex;
    private Map<ArtifactCoords, List<Dependency>> lastNestedDepsByParent;

    /**
     * Result of scanning a ZIP file's contents against unmatched
     * archive entries.
     *
     * @param matchedArchiveEntries archive entries matched by hash
     * @param hashToZipEntryNames content hash to ZIP entry name mapping
     */
    record ZipScanResult(Set<FileEntry> matchedArchiveEntries,
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
            for (FileEntry entry : matchedArchiveEntries) {
                List<String> zipNames = hashToZipEntryNames.get(entry.hash());
                if (zipNames == null) {
                    continue;
                }
                String entryPrefix = null;
                for (String zipName : zipNames) {
                    if (entry.archivePath().endsWith(zipName)) {
                        entryPrefix = entry.archivePath().substring(
                                0, entry.archivePath().length() - zipName.length());
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
                messageDigest, failOnDuplicateHash, List.of(), true, null);
    }

    ArchiveAnalyzer(EffectiveModelResolver effectiveModelResolver,
            RepositorySystem repoSystem,
            MavenProject project,
            MavenSession session,
            MessageDigest messageDigest,
            boolean failOnDuplicateHash,
            List<Bom> externalBoms,
            boolean detectEmbeddedSboms) {
        this(effectiveModelResolver, repoSystem, project, session,
                messageDigest, failOnDuplicateHash, externalBoms, detectEmbeddedSboms, null);
    }

    ArchiveAnalyzer(EffectiveModelResolver effectiveModelResolver,
            RepositorySystem repoSystem,
            MavenProject project,
            MavenSession session,
            MessageDigest messageDigest,
            boolean failOnDuplicateHash,
            List<Bom> externalBoms,
            boolean detectEmbeddedSboms,
            RemoteCoordinatesResolver remoteCoordinatesResolver) {
        this.effectiveModelResolver = effectiveModelResolver;
        this.repoSystem = repoSystem;
        this.project = project;
        this.session = session;
        this.messageDigest = messageDigest;
        this.failOnDuplicateHash = failOnDuplicateHash;
        this.reactorModuleIndex = indexReactorModules(session.getProjects());
        this.externalBoms = externalBoms;
        this.detectEmbeddedSboms = detectEmbeddedSboms;
        this.remoteCoordinatesResolver = remoteCoordinatesResolver;
    }

    /**
     * Indexes reactor projects by artifact id for O(1) lookup.
     */
    private static Map<ArtifactCoords, MavenProject> indexReactorModules(List<MavenProject> projects) {
        Map<ArtifactCoords, MavenProject> index = new HashMap<>(projects.size());
        for (MavenProject p : projects) {
            index.put(MavenArtifactCoords.of(p), p);
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
     * Returns the Aether-typed nested dependencies collected during the last
     * {@link #analyze} call. This is analysis side-data that must NOT be stored
     * on the neutral model.
     *
     * <p>
     * Exposed as a package-private getter so {@link SbomGenerator} can read it
     * for {@code buildDependencyGraph} without polluting the neutral model.
     * </p>
     *
     * @return the nested dependencies map from the last analysis, or {@code null}
     *         if {@code analyze} has not been called
     */
    Map<ArtifactCoords, List<Dependency>> nestedDepsByParent() {
        return lastNestedDepsByParent;
    }

    /**
     * Sets whether the components this analyzer identifies carry their
     * {@link Identification}. When {@code false} none is recorded.
     */
    void setIdentityEvidence(boolean identityEvidence) {
        this.identityEvidence = identityEvidence;
    }

    /**
     * Analyzes archive entries against Maven artifacts and returns
     * the neutral component model.
     *
     * @param entries the archive file entries with content hashes
     * @param baseDirPrefix the base directory prefix to strip, or {@code null}
     * @return the assembled neutral component model
     * @throws IllegalStateException if duplicate hashes are detected
     *         and the matcher is configured to fail on duplicates
     */
    AssemblyComponents analyze(List<FileEntry> entries, String baseDirPrefix) {
        AssemblyComponentsBuilder content = new AssemblyComponentsBuilder(identityEvidence);
        Set<Artifact> matchedArtifacts = new HashSet<>();
        Map<String, FileEntry> unmatchedByPath = new HashMap<>();

        classifyArchiveEntries(entries, baseDirPrefix, content, matchedArtifacts, unmatchedByPath);
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
        if (!unmatchedByPath.isEmpty() && remoteCoordinatesResolver != null) {
            resolveUnmatchedViaRemoteLookup(unmatchedByPath, content);
        }
        if (detectEmbeddedSboms) {
            Set<String> detectedSbomPaths = new HashSet<>();
            detectSbomsInArtifactJars(content, detectedSbomPaths);
            detectedSbomPaths.forEach(unmatchedByPath::remove);
        }

        for (FileEntry entry : unmatchedByPath.values()) {
            content.addUnmatchedFile(entry);
        }

        // Expose the Aether-typed side-data to SbomGenerator without storing
        // it on the neutral model, then assemble and return the model.
        lastNestedDepsByParent = content.nestedDepsByParent();
        return content.build();
    }

    /**
     * Classifies archive entries as matched or unmatched by hash lookup.
     */
    private void classifyArchiveEntries(List<FileEntry> entries,
            String baseDirPrefix,
            AssemblyComponentsBuilder content,
            Set<Artifact> matchedArtifacts,
            Map<String, FileEntry> unmatchedByPath) {
        hashIndex = new ArtifactHashIndex(allArtifacts(), messageDigest, failOnDuplicateHash);
        for (FileEntry entry : entries) {
            String relativePath = stripBaseDir(entry.archivePath(), baseDirPrefix);
            if (relativePath.isEmpty()) {
                continue;
            }
            List<Artifact> artifacts = hashIndex.lookup(entry.hash());
            if (artifacts != null) {
                for (Artifact artifact : artifacts) {
                    matchedArtifacts.add(artifact);
                    content.addMavenEntry(new AssemblyComponentsBuilder.MavenEntry(
                            MavenArtifactCoords.of(artifact), relativePath, entry.hash(),
                            Identification.hashMatch()));
                    detectBundledDepsInArtifactFile(artifact, content);
                }
            } else {
                unmatchedByPath.put(relativePath,
                        new FileEntry(relativePath, entry.hash(), entry.sourceFile()));
            }
        }
    }

    /**
     * Detects artifacts that were unpacked into the assembly.
     * Matched entries are removed from {@code unmatchedByPath}.
     */
    private void detectUnpackedArtifacts(
            Set<Artifact> matchedArtifacts,
            Map<String, FileEntry> unmatchedByPath,
            AssemblyComponentsBuilder content) {

        Path buildDir = Path.of(project.getBuild().getDirectory()).toAbsolutePath().normalize();
        Map<String, List<FileEntry>> entriesByHash = indexEntriesByHash(
                unmatchedByPath.values(), buildDir);

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
     * Reclassifies top-level {@link AssemblyComponentsBuilder.MavenEntry} records
     * whose paths fall inside a detected unpacked artifact. An unpacked
     * artifact is recognized by its {@code archivePath} ending with
     * {@code '/'}. Root-level overlays (empty archivePath) are skipped
     * to avoid reclassifying independent top-level entries. When
     * multiple prefixes match, the longest prefix wins to correctly
     * handle nested unpacked archives.
     *
     * <p>
     * Entries that belong to an unpacked artifact are removed from the
     * top-level list and added as {@link AssemblyComponentsBuilder.NestedMavenEntry}
     * records under the unpacked parent.
     * </p>
     */
    private static void reclassifyEntriesUnderUnpackedArtifacts(AssemblyComponentsBuilder content) {
        // collect unpacked artifact prefixes → parent coords
        Map<String, ArtifactCoords> prefixToParent = null;
        for (AssemblyComponentsBuilder.MavenEntry entry : content.mavenEntries()) {
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
            AssemblyComponentsBuilder.MavenEntry entry = it.next();
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
                    // explicit=false: an unpacked-overlay child expresses
                    // containment via nesting only and must not emit a
                    // dependency edge (matches pre-refactor behavior).
                    content.addNestedEntry(new AssemblyComponentsBuilder.NestedMavenEntry(
                            parentId, entry.artifactId(),
                            entry.archivePath(), entry.hash(), false, entry.identification()));
                }
            }
        }
    }

    /**
     * Indexes entries by content hash, excluding project source files.
     *
     * <p>
     * Entries whose {@link FileEntry#sourceFile() sourceFile}
     * resolves outside the project's build output directory are considered
     * project source files (e.g. {@code LICENSE.txt} included via a
     * {@code <fileSet>}) and are excluded from the index. This prevents
     * false-positive unpack detection when a dependency jar happens to
     * contain a file with the same hash as a project source file.
     * </p>
     */
    private static Map<String, List<FileEntry>> indexEntriesByHash(
            Iterable<FileEntry> entries, Path buildDir) {
        Map<String, List<FileEntry>> index = new HashMap<>();
        for (FileEntry e : entries) {
            if (e.hash() != null && !isProjectSourceFile(e, buildDir)) {
                index.computeIfAbsent(e.hash(), k -> new ArrayList<>(1)).add(e);
            }
        }
        return index;
    }

    /**
     * Returns {@code true} if the entry originates from a project source
     * file rather than a build output. An entry is considered a project
     * source file when its {@code sourceFile} is known and does not
     * reside under the project's build directory.
     */
    private static boolean isProjectSourceFile(FileEntry entry, Path buildDir) {
        if (entry.sourceFile() == null) {
            return false;
        }
        return !entry.sourceFile().toPath().startsWith(buildDir);
    }

    /**
     * Scans unmatched JAR entries for embedded {@code pom.properties}
     * to identify non-dependency JARs as Maven components.
     * Identified entries are removed from {@code unmatchedByPath}.
     */
    private static void detectMavenMetadataInUnmatchedJars(
            Map<String, FileEntry> unmatchedByPath,
            AssemblyComponentsBuilder content) {
        Set<String> alreadyProcessed = content.fileNestedByPath().keySet();
        var it = unmatchedByPath.values().iterator();
        while (it.hasNext()) {
            FileEntry fileEntry = it.next();
            if (fileEntry.sourceFile() == null
                    || !fileEntry.sourceFile().isFile()
                    || !hasZipBasedExtension(fileEntry.archivePath())
                    || alreadyProcessed.contains(fileEntry.archivePath())) {
                continue;
            }
            try (ZipFile zf = new ZipFile(fileEntry.sourceFile())) {
                List<Properties> allProps = readPomPropertiesFromZip(zf);
                if (allProps.isEmpty()) {
                    continue;
                }
                boolean identified = allProps.size() == 1
                        ? registerFromStandaloneProps(allProps.get(0), fileEntry, content,
                                Identification.pomProperties()) != null
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
     * Looks up still-unmatched entries (files that no local/offline
     * technique could identify) by SHA-1 checksum against the configured
     * remote repositories. Identified entries are removed from
     * {@code unmatchedByPath}, exactly as {@link #detectMavenMetadataInUnmatchedJars}
     * does for local {@code pom.properties} hits — this is the last resort,
     * run only once every free, local technique has had its chance.
     */
    private void resolveUnmatchedViaRemoteLookup(
            Map<String, FileEntry> unmatchedByPath,
            AssemblyComponentsBuilder content) {
        var it = unmatchedByPath.entrySet().iterator();
        while (it.hasNext()) {
            var mapEntry = it.next();
            FileEntry fileEntry = mapEntry.getValue();
            if (!remoteCoordinatesResolver.isCandidate(fileEntry.archivePath())) {
                continue;
            }
            Optional<ArtifactCoords> coords = remoteCoordinatesResolver.resolve(fileEntry);
            if (coords.isEmpty()) {
                continue;
            }
            content.addMavenEntry(new AssemblyComponentsBuilder.MavenEntry(
                    coords.get(), fileEntry.archivePath(), fileEntry.hash(),
                    Identification.remoteCoordinatesLookup()));
            it.remove();
        }
    }

    /**
     * Registers a standalone JAR as a Maven entry from pom.properties.
     *
     * @return the registered artifact coordinates, or {@code null} if
     *         required properties are missing
     */
    private static ArtifactCoords registerFromStandaloneProps(Properties props,
            FileEntry fileEntry, AssemblyComponentsBuilder content, Identification identification) {
        String gId = props.getProperty("groupId");
        String aId = props.getProperty("artifactId");
        String ver = props.getProperty("version");
        if (gId == null || aId == null || ver == null) {
            return null;
        }
        ArtifactCoords coords = ArtifactCoords.of(gId, aId, ver);
        content.addMavenEntry(new AssemblyComponentsBuilder.MavenEntry(
                coords, fileEntry.archivePath(), fileEntry.hash(), identification));
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
            FileEntry fileEntry, AssemblyComponentsBuilder content) {
        return resolveAndRegisterShadedOwner(allProps, fileEntry, content,
                fileEntry.archivePath(),
                props -> registerFromStandaloneProps(props, fileEntry, content,
                        Identification.pomPropertiesFilenameOwner()));
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
            List<Properties> allProps, FileEntry archiveEntry,
            AssemblyComponentsBuilder content, String pathForFilename,
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
            Map<String, List<FileEntry>> entriesByHash,
            Set<Artifact> matchedArtifacts,
            Map<String, FileEntry> unmatchedByPath,
            AssemblyComponentsBuilder content) {
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
            content.addMavenEntry(new AssemblyComponentsBuilder.MavenEntry(
                    MavenArtifactCoords.of(artifact), occurrence, hashIndex.hashOf(artifact),
                    Identification.unpackedContentMatch()));

            Map<String, Artifact> nestedArtifactsByHash = buildNestedArtifactHashMap(artifact);
            ArtifactCoords parentCoords = MavenArtifactCoords.of(artifact);

            for (FileEntry archiveEntry : scan.matchedArchiveEntries) {
                boolean identified = identifyNestedArtifact(archiveEntry, zf,
                        scan.hashToZipEntryNames, nestedArtifactsByHash,
                        parentCoords, matchedArtifacts, content);
                if (identified) {
                    unmatchedByPath.remove(archiveEntry.archivePath());
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
            Map<String, List<FileEntry>> entriesByHash)
            throws IOException {
        Set<FileEntry> matchedArchiveEntries = new HashSet<>();
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
            List<FileEntry> matching = entriesByHash.get(hash);
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
    private boolean identifyNestedArtifact(FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            Map<String, Artifact> nestedArtifactsByHash,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            AssemblyComponentsBuilder content) {
        if (archiveEntry.hash() != null) {
            Artifact nestedArtifact = nestedArtifactsByHash.get(archiveEntry.hash());
            if (nestedArtifact != null) {
                registerNestedArtifact(nestedArtifact, archiveEntry, parentId, matchedArtifacts, content,
                        Identification.hashMatch());
                detectBundledDependencies(archiveEntry, parentZip, hashToZipEntryNames,
                        MavenArtifactCoords.of(nestedArtifact), content);
                return true;
            }
        }
        return tryIdentifyFromPomProperties(archiveEntry, parentZip,
                hashToZipEntryNames, parentId, matchedArtifacts, content);
    }

    /**
     * Scans an artifact's JAR file directly for bundled (shaded) dependencies.
     */
    private void detectBundledDepsInArtifactFile(Artifact artifact, AssemblyComponentsBuilder content) {
        File file = artifact.getFile();
        if (file == null) {
            return;
        }
        ArtifactCoords owner = MavenArtifactCoords.of(artifact);
        for (ArtifactCoords bundled : BundledArtifactScanner.bundledNonOwner(file.toPath(), owner)) {
            content.addNestedEntry(new AssemblyComponentsBuilder.NestedMavenEntry(
                    owner, bundled, null, null, false, Identification.pomProperties()));
        }
    }

    /**
     * Scans a hash-identified nested JAR for bundled (shaded) dependencies
     * by reading its pom.properties via the parent ZIP.
     */
    private void detectBundledDependencies(FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            ArtifactCoords ownerCoords, AssemblyComponentsBuilder content) {
        if (archiveEntry.hash() == null) {
            return;
        }
        List<String> zipEntryNames = hashToZipEntryNames.get(archiveEntry.hash());
        if (zipEntryNames == null) {
            return;
        }
        ZipEntry nested = parentZip.getEntry(zipEntryNames.get(0));
        if (nested == null) {
            return;
        }
        try (InputStream is = parentZip.getInputStream(nested)) {
            registerBundled(ownerCoords, BundledArtifactScanner.bundledNonOwner(is, ownerCoords), content);
        } catch (IOException e) {
            log.debug("Could not scan nested JAR {} for bundled dependencies",
                    zipEntryNames.get(0), e);
        }
    }

    /**
     * Registers already-read descriptors' non-owner entries as bundled nested
     * components, reusing the shared {@link BundledArtifactScanner} filter.
     */
    private static void registerBundledDependencies(ArtifactCoords ownerCoords, List<Properties> allProps,
            AssemblyComponentsBuilder content) {
        registerBundled(ownerCoords, BundledArtifactScanner.nonOwner(allProps, ownerCoords), content);
    }

    private static void registerBundled(ArtifactCoords ownerCoords, List<ArtifactCoords> bundled,
            AssemblyComponentsBuilder content) {
        for (ArtifactCoords coords : bundled) {
            // Coordinates come verbatim from the bundled artifact's own
            // pom.properties, however the owner was identified.
            content.addNestedEntry(new AssemblyComponentsBuilder.NestedMavenEntry(
                    ownerCoords, coords, null, null, false, Identification.pomProperties()));
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
    private static void recordAllAsFileNested(FileEntry archiveEntry, List<Properties> allProps,
            AssemblyComponentsBuilder content) {
        for (Properties p : allProps) {
            String gId = p.getProperty("groupId");
            String aId = p.getProperty("artifactId");
            String ver = p.getProperty("version");
            if (gId != null && aId != null && ver != null) {
                content.addFileNestedArtifact(archiveEntry.archivePath(),
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
    private boolean tryIdentifyFromPomProperties(FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            ArtifactCoords parentId,
            Set<Artifact> matchedArtifacts,
            AssemblyComponentsBuilder content) {
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
                        parentId, matchedArtifacts, content, Identification.pomProperties()) != null;
            }
            // Shaded JAR: match the filename against artifactIds
            return resolveAndRegisterShadedOwner(allProps, archiveEntry, content,
                    zipEntryName,
                    props -> tryRegisterFromProps(props, archiveEntry,
                            parentId, matchedArtifacts, content,
                            Identification.pomPropertiesFilenameOwner()));
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
            FileEntry archiveEntry,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            AssemblyComponentsBuilder content, Identification identification) {
        String gId = pomProps.getProperty("groupId");
        String aId = pomProps.getProperty("artifactId");
        String ver = pomProps.getProperty("version");
        if (gId == null || aId == null || ver == null) {
            return null;
        }
        Artifact nested = new DefaultArtifact(
                gId, aId, ver, "compile", JAR, null,
                new DefaultArtifactHandler(JAR));
        registerNestedArtifact(nested, archiveEntry, parentId, matchedArtifacts, content, identification);
        return MavenArtifactCoords.of(nested);
    }

    /**
     * Records a nested artifact and its dependency relationship.
     */
    private void registerNestedArtifact(Artifact artifact, FileEntry archiveEntry,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            AssemblyComponentsBuilder content, Identification identification) {
        matchedArtifacts.add(artifact);
        ArtifactCoords nestedId = MavenArtifactCoords.of(artifact);
        content.addNestedEntry(new AssemblyComponentsBuilder.NestedMavenEntry(
                parentId, nestedId, archiveEntry.archivePath(), archiveEntry.hash(), true, identification));
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
        ArtifactCoords coords = MavenArtifactCoords.of(artifact);
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
                Artifact mavenArtifact = new DefaultArtifact(
                        dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                        dep.getScope() != null ? dep.getScope() : "compile",
                        dep.getType() != null ? dep.getType() : JAR,
                        dep.getClassifier(),
                        new DefaultArtifactHandler(
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
            Map<String, FileEntry> unmatchedByPath,
            AssemblyComponentsBuilder content) {
        if (externalBoms.isEmpty()) {
            return;
        }
        Map<String, ExternalComponentRef> externalHashIndex = buildExternalHashIndex();
        if (externalHashIndex.isEmpty()) {
            return;
        }
        // Collect all archive paths per matched component before mutating
        Map<Component, List<String>> matchedPaths = new HashMap<>();
        var it = unmatchedByPath.entrySet().iterator();
        while (it.hasNext()) {
            var entry = it.next();
            ExternalComponentRef ref = externalHashIndex.get(entry.getValue().hash());
            if (ref != null) {
                matchedPaths.computeIfAbsent(ref.component(), k -> new ArrayList<>())
                        .add(entry.getKey());
                it.remove();
            }
        }
        // Replace stale occurrences with the collected archive paths
        for (var matched : matchedPaths.entrySet()) {
            setOccurrences(matched.getKey(), matched.getValue());
        }
    }

    private static void setOccurrences(Component component, List<String> archivePaths) {
        Evidence evidence = component.getEvidence();
        if (evidence == null) {
            evidence = new Evidence();
            component.setEvidence(evidence);
        }
        List<Occurrence> occurrences = new ArrayList<>(archivePaths.size());
        for (String path : archivePaths) {
            Occurrence occ = new Occurrence();
            occ.setLocation(path);
            occurrences.add(occ);
        }
        evidence.setOccurrences(occurrences);
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
        String normalizedAlg = SbomUtils.normalizeAlgorithm(
                messageDigest.getAlgorithm());
        for (Bom bom : externalBoms) {
            if (bom.getComponents() == null) {
                continue;
            }
            indexComponentTree(bom.getComponents(), bom, normalizedAlg, index);
        }
        return index;
    }

    private static void indexComponentTree(List<Component> components, Bom bom,
            String normalizedAlg, Map<String, ExternalComponentRef> index) {
        for (Component comp : components) {
            String hash = SbomUtils.extractHash(comp, normalizedAlg);
            if (hash != null) {
                index.putIfAbsent(hash, new ExternalComponentRef(comp, bom));
            }
            if (comp.getComponents() != null) {
                indexComponentTree(comp.getComponents(), bom,
                        normalizedAlg, index);
            }
        }
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
    private void detectSbomsInArtifactJars(AssemblyComponentsBuilder content,
            Set<String> detectedSbomPaths) {
        Map<ArtifactCoords, String> coordsToPath = new HashMap<>();
        for (AssemblyComponentsBuilder.MavenEntry entry : content.mavenEntries()) {
            coordsToPath.put(entry.artifactId(), entry.archivePath());
        }
        Set<ArtifactCoords> knownCoords = content.collectKnownArtifactCoords();
        Set<File> scannedFiles = new HashSet<>();
        for (Artifact artifact : allArtifacts()) {
            ArtifactCoords coords = MavenArtifactCoords.of(artifact);
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
            AssemblyComponentsBuilder content, String parentArchivePath,
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
                        content.addDiscoveredSbom(new DiscoveredSbom(
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

    /**
     * Private mutable builder for the neutral {@link AssemblyComponents} model.
     * It accumulates the analyzer's classified detections (matched Maven
     * artifacts, nested artifacts inside unpacked archives, unmatched files,
     * discovered embedded SBOMs) plus Aether dependency side-data, and
     * assembles them into an immutable {@link AssemblyComponents} via
     * {@link #build()}.
     */
    private static class AssemblyComponentsBuilder {

        /**
         * An archive entry identified as a Maven artifact.
         *
         * @param identification how the entry was identified, or {@code null}
         */
        record MavenEntry(ArtifactCoords artifactId, String archivePath, String hash,
                Identification identification) {
        }

        /**
         * A Maven artifact found nested inside an unpacked parent archive
         * (e.g., a JAR inside an unpacked WAR).
         *
         * @param explicit {@code true} if this entry was positively identified
         *        by hash and should produce a {@link DependencyEdge};
         *        {@code false} for bundled (shaded) deps discovered only via
         *        pom.properties, where nesting is sufficient
         * @param identification how the entry was identified, or {@code null}
         */
        record NestedMavenEntry(ArtifactCoords parentId, ArtifactCoords artifactId,
                String archivePath, String hash, boolean explicit, Identification identification) {
        }

        private final List<MavenEntry> mavenEntries = new ArrayList<>();
        private final List<NestedMavenEntry> nestedEntries = new ArrayList<>();
        private final List<FileEntry> unmatchedFiles = new ArrayList<>();
        private final Map<ArtifactCoords, List<Dependency>> nestedDepsByParent = new HashMap<>();
        // Maven artifacts discovered inside a file (e.g. via pom.properties in a
        // shaded/fat JAR that could not be positively identified), keyed by the
        // file's archive path so they nest under that file's component.
        private final Map<String, List<ArtifactCoords>> fileNestedByPath = new LinkedHashMap<>();
        private final List<DiscoveredSbom> discoveredSboms = new ArrayList<>();
        // Whether built components carry their Identification.
        private final boolean identityEvidence;

        AssemblyComponentsBuilder(boolean identityEvidence) {
            this.identityEvidence = identityEvidence;
        }

        List<MavenEntry> mavenEntries() {
            return mavenEntries;
        }

        List<NestedMavenEntry> nestedEntries() {
            return nestedEntries;
        }

        List<FileEntry> unmatchedFiles() {
            return unmatchedFiles;
        }

        Map<ArtifactCoords, List<Dependency>> nestedDepsByParent() {
            return nestedDepsByParent;
        }

        Map<String, List<ArtifactCoords>> fileNestedByPath() {
            return fileNestedByPath;
        }

        void addMavenEntry(MavenEntry entry) {
            mavenEntries.add(entry);
        }

        void addNestedEntry(NestedMavenEntry entry) {
            nestedEntries.add(entry);
        }

        void addUnmatchedFile(FileEntry entry) {
            unmatchedFiles.add(entry);
        }

        void addFileNestedArtifact(String archivePath, ArtifactCoords artifactId) {
            fileNestedByPath.computeIfAbsent(archivePath, k -> new ArrayList<>())
                    .add(artifactId);
        }

        List<DiscoveredSbom> discoveredSboms() {
            return discoveredSboms;
        }

        void addDiscoveredSbom(DiscoveredSbom sbom) {
            discoveredSboms.add(sbom);
        }

        void addNestedDependency(ArtifactCoords parentId, Dependency dependency) {
            nestedDepsByParent.computeIfAbsent(parentId, k -> new ArrayList<>())
                    .add(dependency);
        }

        /**
         * Collects all known artifact ids from both top-level and nested
         * entries, for use in dependency graph filtering.
         */
        Set<ArtifactCoords> collectKnownArtifactCoords() {
            Set<ArtifactCoords> ids = new HashSet<>(mavenEntries.size() + nestedEntries.size() + fileNestedByPath.size());
            for (MavenEntry e : mavenEntries) {
                ids.add(e.artifactId());
            }
            for (NestedMavenEntry e : nestedEntries) {
                ids.add(e.artifactId());
            }
            for (List<ArtifactCoords> nested : fileNestedByPath.values()) {
                ids.addAll(nested);
            }
            return ids;
        }

        /**
         * Assembles the accumulated detections into the neutral
         * {@link AssemblyComponents} model, preserving order and nesting so the
         * {@link BomRenderer} produces byte-identical output.
         *
         * <p>
         * Assembly rules:
         * <ul>
         * <li>each {@code MavenEntry} → a top-level {@link PackageComponent}</li>
         * <li>each {@code NestedMavenEntry} → a {@link PackageComponent} nested
         * under its parent, plus (only when {@code explicit}) a
         * {@link DependencyEdge}</li>
         * <li>each file-nested artifact → a {@link PackageComponent} (no hash)
         * nested under the {@link FileComponent} at that path</li>
         * <li>each unmatched file → a top-level {@link FileComponent}</li>
         * <li>each discovered embedded SBOM → carried over verbatim</li>
         * </ul>
         * </p>
         *
         * <p>
         * The Aether-typed {@link #nestedDepsByParent()} is intentionally not
         * placed on the model; the analyzer exposes it separately for
         * {@link SbomGenerator} to consume.
         * </p>
         *
         * @return the assembled neutral model
         */
        AssemblyComponents build() {
            // 1. Top-level PackageComponents (no licenses yet).
            List<AssemblyComponent> topLevel = new ArrayList<>();
            for (MavenEntry entry : mavenEntries) {
                topLevel.add(PackageComponent.of(entry.artifactId(), entry.archivePath(), entry.hash(),
                        true, identityEvidence ? entry.identification() : null));
            }

            // 2. Attach nested children to their top-level parents.
            Map<ArtifactCoords, List<NestedMavenEntry>> childrenByParent = new HashMap<>();
            for (NestedMavenEntry nested : nestedEntries) {
                childrenByParent.computeIfAbsent(nested.parentId(), k -> new ArrayList<>())
                        .add(nested);
            }
            if (!childrenByParent.isEmpty()) {
                Map<ArtifactCoords, PackageComponent> builtNested = new HashMap<>();
                for (int i = 0; i < topLevel.size(); i++) {
                    if (topLevel.get(i) instanceof PackageComponent pkg) {
                        ArtifactCoords coords = (ArtifactCoords) pkg.ref();
                        List<AssemblyComponent> nestedList = buildNestedComponentsRecursively(
                                coords, childrenByParent, builtNested);
                        if (!nestedList.isEmpty()) {
                            topLevel.set(i, pkg.withNested(nestedList));
                        }
                    }
                }
            }

            // 3. File components, with their file-nested artifacts.
            for (FileEntry fileEntry : unmatchedFiles) {
                List<ArtifactCoords> nestedCoords = fileNestedByPath
                        .getOrDefault(fileEntry.archivePath(), List.of());
                List<AssemblyComponent> nestedPkgs = new ArrayList<>(nestedCoords.size());
                // The owner could not be resolved, but each artifact's coordinates
                // were read verbatim from its own pom.properties.
                for (ArtifactCoords coords : nestedCoords) {
                    nestedPkgs.add(PackageComponent.of(coords, null, null, true,
                            identityEvidence ? Identification.pomProperties() : null));
                }
                topLevel.add(new FileComponent(
                        fileEntry.archivePath(), fileEntry.hash(), nestedPkgs));
            }

            AssemblyComponents model = new AssemblyComponents();
            for (AssemblyComponent comp : topLevel) {
                model.addComponent(comp);
            }

            // 4. Dependency edges — only for explicitly-identified nested entries.
            for (NestedMavenEntry nested : nestedEntries) {
                if (nested.explicit()) {
                    model.addDependencyEdge(
                            new DependencyEdge(nested.parentId(), nested.artifactId(), true));
                }
            }

            // 5. Discovered embedded SBOMs.
            for (DiscoveredSbom discovered : discoveredSboms) {
                model.addDiscoveredSbom(discovered);
            }

            return model;
        }

        /**
         * Recursively builds nested {@link PackageComponent}s for a parent,
         * handling multi-level nesting (e.g. bundled deps within shaded JARs
         * that are themselves nested within WARs).
         *
         * <p>
         * Assumes an acyclic parent-child relationship: the detection pipeline
         * derives {@code childrenByParent} from filesystem artifacts, which
         * cannot form cycles. The {@code builtComponents} cache also ensures
         * each parent's subtree is built once and shared. A circular
         * relationship would recurse without terminating; the no-cycle contract
         * is guaranteed by the filesystem-based source rather than an explicit
         * guard.
         * </p>
         */
        private List<AssemblyComponent> buildNestedComponentsRecursively(
                ArtifactCoords parentCoords,
                Map<ArtifactCoords, List<NestedMavenEntry>> childrenByParent,
                Map<ArtifactCoords, PackageComponent> builtComponents) {
            List<AssemblyComponent> result = new ArrayList<>();
            List<NestedMavenEntry> directChildren = childrenByParent.get(parentCoords);
            if (directChildren == null) {
                return result;
            }
            for (NestedMavenEntry child : directChildren) {
                // Reuse an already-built component to handle shared children.
                PackageComponent built = builtComponents.get(child.artifactId());
                if (built != null) {
                    result.add(built);
                    continue;
                }
                List<AssemblyComponent> grandchildren = buildNestedComponentsRecursively(
                        child.artifactId(), childrenByParent, builtComponents);
                PackageComponent childComponent = new PackageComponent(
                        child.artifactId(), child.archivePath(), child.hash(),
                        List.of(), grandchildren, true, identityEvidence ? child.identification() : null);
                builtComponents.put(child.artifactId(), childComponent);
                result.add(childComponent);
            }
            return result;
        }
    }
}
