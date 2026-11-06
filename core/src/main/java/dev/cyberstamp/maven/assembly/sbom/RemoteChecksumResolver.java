package dev.cyberstamp.maven.assembly.sbom;

import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Identifies otherwise-unmatched archive entries (e.g. jars built with
 * Gradle or Ant, which carry no Maven {@code pom.properties}) by looking up
 * their SHA-1 content hash against one or more remote package repositories.
 *
 * <p>
 * Built once per SBOM generation run via {@link #create}, which returns
 * empty when remote lookup is disabled or not usable (no include patterns,
 * or no backend configured) — callers should treat an empty result as
 * "feature off" and skip this step entirely.
 * </p>
 *
 * <p>
 * Not thread-safe: intended for the same single-threaded use as the rest of
 * the {@link ArchiveAnalyzer} pipeline.
 * </p>
 */
final class RemoteChecksumResolver {

    private static final Logger log = LoggerFactory.getLogger(RemoteChecksumResolver.class);

    private final List<PathMatcher> includeMatchers;
    private final List<PathMatcher> excludeMatchers;
    private final List<ChecksumArtifactLookup> backends;
    private final int maxLookups;
    private final MessageDigest sha1Digest;
    private final Map<String, Optional<ArtifactCoords>> cache = new HashMap<>();

    private int callsUsed;
    private boolean capWarningLogged;

    private RemoteChecksumResolver(List<PathMatcher> includeMatchers, List<PathMatcher> excludeMatchers,
            List<ChecksumArtifactLookup> backends, int maxLookups, MessageDigest sha1Digest) {
        this.includeMatchers = includeMatchers;
        this.excludeMatchers = excludeMatchers;
        this.backends = backends;
        this.maxLookups = maxLookups;
        this.sha1Digest = sha1Digest;
    }

    /**
     * Builds a resolver from user configuration and already-decrypted
     * repository credentials, or returns empty if the feature is disabled or
     * not usable as configured.
     *
     * @param config the user configuration, or {@code null}
     * @param nexusUsername decrypted Nexus username, or {@code null} for
     *        anonymous access
     * @param nexusPassword decrypted Nexus password, or {@code null}
     * @param artifactoryUsername decrypted Artifactory username, or
     *        {@code null} for anonymous access
     * @param artifactoryPassword decrypted Artifactory password, or
     *        {@code null}
     * @return the resolver, or empty if disabled/unusable
     */
    static Optional<RemoteChecksumResolver> create(RemoteArtifactLookup config,
            String nexusUsername, String nexusPassword,
            String artifactoryUsername, String artifactoryPassword) {
        if (config == null || !config.isEnabled()) {
            return Optional.empty();
        }
        List<String> includes = config.includesOrEmpty();
        if (includes.isEmpty()) {
            log.warn("remoteLookup is enabled but no include patterns are configured; "
                    + "remote checksum lookup will not run. Configure at least one "
                    + "glob pattern in remoteLookup.includes to enable it.");
            return Optional.empty();
        }
        List<ChecksumArtifactLookup> backends = buildBackends(
                config, nexusUsername, nexusPassword, artifactoryUsername, artifactoryPassword);
        if (backends.isEmpty()) {
            log.warn("remoteLookup is enabled but no backend is configured "
                    + "(central is disabled and neither nexusUrl nor artifactoryUrl is set); "
                    + "remote checksum lookup will not run.");
            return Optional.empty();
        }
        List<PathMatcher> includeMatchers = compileMatchers(includes);
        List<PathMatcher> excludeMatchers = compileMatchers(config.excludesOrEmpty());
        if (includeMatchers.isEmpty()) {
            log.warn("None of the configured remoteLookup.includes patterns are valid globs; "
                    + "remote checksum lookup will not run.");
            return Optional.empty();
        }
        MessageDigest sha1Digest;
        try {
            sha1Digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is guaranteed to be available on every standard JDK.
            throw new IllegalStateException("SHA-1 digest not available", e);
        }
        return Optional.of(new RemoteChecksumResolver(
                includeMatchers, excludeMatchers, backends, config.getMaxLookups(), sha1Digest));
    }

    private static List<ChecksumArtifactLookup> buildBackends(RemoteArtifactLookup config,
            String nexusUsername, String nexusPassword,
            String artifactoryUsername, String artifactoryPassword) {
        Duration timeout = Duration.ofMillis(Math.max(1, config.getTimeoutMillis()));
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
        List<ChecksumArtifactLookup> backends = new ArrayList<>(3);
        if (config.isCentral()) {
            backends.add(new MavenCentralChecksumLookup(client, timeout));
        }
        if (isSet(config.getNexusUrl())) {
            String auth = authHeader(nexusUsername, nexusPassword);
            backends.add(new NexusChecksumLookup(client, timeout, config.getNexusUrl(), auth));
        }
        if (isSet(config.getArtifactoryUrl())) {
            String auth = authHeader(artifactoryUsername, artifactoryPassword);
            backends.add(new ArtifactoryChecksumLookup(client, timeout, config.getArtifactoryUrl(), auth));
        }
        return backends;
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private static String authHeader(String username, String password) {
        if (!isSet(username) || password == null) {
            return null;
        }
        return HttpChecksumLookupSupport.basicAuthHeader(username, password);
    }

    private static List<PathMatcher> compileMatchers(List<String> globs) {
        List<PathMatcher> matchers = new ArrayList<>(globs.size());
        for (String glob : globs) {
            if (glob == null || glob.isBlank()) {
                continue;
            }
            try {
                matchers.add(FileSystems.getDefault().getPathMatcher("glob:" + glob.trim()));
            } catch (IllegalArgumentException e) {
                log.warn("Ignoring invalid remoteLookup glob pattern '{}': {}", glob, e.getMessage());
            }
        }
        return matchers;
    }

    /**
     * Returns whether the given archive-relative path is eligible for remote
     * lookup: it must match at least one include pattern and no exclude
     * pattern.
     *
     * @param archivePath the archive-relative path
     * @return {@code true} if eligible
     */
    boolean isCandidate(String archivePath) {
        Path path = Path.of(archivePath);
        boolean included = false;
        for (PathMatcher matcher : includeMatchers) {
            if (matcher.matches(path)) {
                included = true;
                break;
            }
        }
        if (!included) {
            return false;
        }
        for (PathMatcher matcher : excludeMatchers) {
            if (matcher.matches(path)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Attempts to identify the given file entry by its content's SHA-1 hash,
     * trying each configured backend in order until one succeeds.
     *
     * <p>
     * Results are cached by SHA-1 for the lifetime of this resolver, and the
     * total number of HTTP calls is capped at {@code maxLookups} regardless
     * of how many candidate entries are presented.
     * </p>
     *
     * @param entry the candidate file entry; must have a readable
     *        {@link FileEntry#sourceFile()}
     * @return the matched coordinates, or empty if not found, the entry has
     *         no readable source file, or the call budget is exhausted
     */
    Optional<ArtifactCoords> resolve(FileEntry entry) {
        if (entry.sourceFile() == null || !entry.sourceFile().isFile()) {
            return Optional.empty();
        }
        String sha1;
        try {
            sha1 = SbomUtils.computeHash(sha1Digest, entry.sourceFile().toPath());
        } catch (IOException e) {
            log.debug("Could not hash {} for remote checksum lookup", entry.sourceFile(), e);
            return Optional.empty();
        }
        Optional<ArtifactCoords> cached = cache.get(sha1);
        if (cached != null) {
            return cached;
        }
        Optional<ArtifactCoords> result = lookupBackends(sha1);
        cache.put(sha1, result);
        return result;
    }

    private Optional<ArtifactCoords> lookupBackends(String sha1) {
        for (ChecksumArtifactLookup backend : backends) {
            if (callsUsed >= maxLookups) {
                if (!capWarningLogged) {
                    log.warn("Remote checksum lookup call budget ({}) exhausted; "
                            + "remaining unmatched files will not be looked up", maxLookups);
                    capWarningLogged = true;
                }
                return Optional.empty();
            }
            callsUsed++;
            Optional<ArtifactCoords> result = backend.lookup(sha1);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }
}
