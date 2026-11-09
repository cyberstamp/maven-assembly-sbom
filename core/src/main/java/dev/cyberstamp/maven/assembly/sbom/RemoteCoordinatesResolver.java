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
 * empty when remote lookup is disabled or not usable (no backend configured —
 * missing include patterns instead default to {@code **&#47;*.jar}) — callers
 * should treat an empty result as "feature off" and skip this step entirely.
 * </p>
 *
 * <p>
 * Not thread-safe: intended for the same single-threaded use as the rest of
 * the {@link ArchiveAnalyzer} pipeline.
 * </p>
 */
final class RemoteCoordinatesResolver {

    private static final Logger log = LoggerFactory.getLogger(RemoteCoordinatesResolver.class);

    /**
     * Fallback include pattern used when {@link RemoteArtifactLookup#getIncludes()}
     * is unset, so that enabling the feature alone is enough to try it.
     */
    private static final List<String> DEFAULT_INCLUDES = List.of("**/*.jar");

    private final List<PathMatcher> includeMatchers;
    private final List<PathMatcher> excludeMatchers;
    private final List<CoordinatesLookup> backends;
    private final int maxLookups;
    private final MessageDigest sha1Digest;
    private final Map<String, Optional<ArtifactCoords>> cache = new HashMap<>();

    private int callsUsed;
    private boolean capWarningLogged;

    private RemoteCoordinatesResolver(List<PathMatcher> includeMatchers, List<PathMatcher> excludeMatchers,
            List<CoordinatesLookup> backends, int maxLookups, MessageDigest sha1Digest) {
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
    static Optional<RemoteCoordinatesResolver> create(RemoteArtifactLookup config,
            String nexusUsername, String nexusPassword,
            String artifactoryUsername, String artifactoryPassword) {
        if (config == null || !config.isEnabled()) {
            return Optional.empty();
        }
        List<CoordinatesLookup> backends = buildBackends(
                config, nexusUsername, nexusPassword, artifactoryUsername, artifactoryPassword);
        if (backends.isEmpty()) {
            log.warn("remoteMavenCoordinatesLookup is enabled but no backend is configured "
                    + "(central is disabled and neither nexusUrl nor artifactoryUrl is set); "
                    + "remote lookup will not run.");
            return Optional.empty();
        }
        List<String> includes = config.includesOrEmpty();
        if (includes.isEmpty()) {
            includes = DEFAULT_INCLUDES;
            log.info("remoteMavenCoordinatesLookup.includes not configured; defaulting to {}", DEFAULT_INCLUDES);
        }
        List<PathMatcher> includeMatchers = compileMatchers(includes);
        List<PathMatcher> excludeMatchers = compileMatchers(config.excludesOrEmpty());
        if (includeMatchers.isEmpty()) {
            log.warn("None of the configured remoteMavenCoordinatesLookup.includes patterns are valid globs; "
                    + "remote lookup will not run.");
            return Optional.empty();
        }
        MessageDigest sha1Digest;
        try {
            sha1Digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is guaranteed to be available on every standard JDK.
            throw new IllegalStateException("SHA-1 digest not available", e);
        }
        return Optional.of(new RemoteCoordinatesResolver(
                includeMatchers, excludeMatchers, backends, config.getMaxLookups(), sha1Digest));
    }

    private static List<CoordinatesLookup> buildBackends(RemoteArtifactLookup config,
            String nexusUsername, String nexusPassword,
            String artifactoryUsername, String artifactoryPassword) {
        Duration timeout = Duration.ofMillis(Math.max(1, config.getTimeoutMillis()));
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
        List<CoordinatesLookup> backends = new ArrayList<>(3);
        if (config.isCentral()) {
            String centralUrl = config.getCentralUrl();
            if (!isSet(centralUrl)) {
                backends.add(new MavenCentralCoordinatesLookup(client, timeout));
            } else if (centralUrl.contains(MavenCentralCoordinatesLookup.PLACEHOLDER)) {
                backends.add(new MavenCentralCoordinatesLookup(client, timeout, centralUrl));
            } else {
                log.warn("centralUrl must be a complete search URL containing a {} placeholder "
                        + "(e.g. {}); Maven Central lookup will not run.",
                        MavenCentralCoordinatesLookup.PLACEHOLDER, MavenCentralCoordinatesLookup.DEFAULT_SEARCH_URL);
            }
        }
        if (isSet(config.getNexusUrl())) {
            if (config.getNexusUrl().contains(NexusCoordinatesLookup.PLACEHOLDER)) {
                String auth = authHeader(nexusUsername, nexusPassword);
                backends.add(new NexusCoordinatesLookup(client, timeout, config.getNexusUrl(), auth));
            } else {
                log.warn("nexusUrl must be a complete search URL containing a {} placeholder "
                        + "(e.g. https://nexus.example.com/service/rest/v1/search?sha1={}); "
                        + "Nexus lookup will not run.", NexusCoordinatesLookup.PLACEHOLDER, NexusCoordinatesLookup.PLACEHOLDER);
            }
        }
        if (isSet(config.getArtifactoryUrl())) {
            if (config.getArtifactoryUrl().contains(ArtifactoryCoordinatesLookup.PLACEHOLDER)) {
                String auth = authHeader(artifactoryUsername, artifactoryPassword);
                backends.add(new ArtifactoryCoordinatesLookup(client, timeout, config.getArtifactoryUrl(), auth));
            } else {
                log.warn("artifactoryUrl must be a complete search URL containing a {} placeholder "
                        + "(e.g. https://artifactory.example.com/artifactory/api/search/checksum?sha1={}); "
                        + "Artifactory lookup will not run.",
                        ArtifactoryCoordinatesLookup.PLACEHOLDER, ArtifactoryCoordinatesLookup.PLACEHOLDER);
            }
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
        return HttpLookupSupport.basicAuthHeader(username, password);
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
                log.warn("Ignoring invalid remoteMavenCoordinatesLookup glob pattern '{}': {}", glob, e.getMessage());
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
            log.debug("Could not hash {} for remote lookup", entry.sourceFile(), e);
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
        for (CoordinatesLookup backend : backends) {
            if (callsUsed >= maxLookups) {
                if (!capWarningLogged) {
                    log.warn("Remote lookup call budget ({}) exhausted; "
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
