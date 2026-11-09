package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Looks up Maven coordinates by SHA-1 against an internal JFrog Artifactory
 * instance, using its checksum search API.
 *
 * <p>
 * Unlike Maven Central and Nexus, Artifactory's checksum search does not
 * return structured group/artifact/version fields; it returns the storage
 * {@code uri} of the matching item instead. Coordinates are recovered from
 * that path by assuming the standard Maven2 repository layout:
 * {@code .../api/storage/<repoKey>/<groupPath>/<artifactId>/<version>/<file>}.
 * </p>
 *
 * <p>
 * The configured URL must be a complete search request containing a literal
 * {@code {sha1}} placeholder for the content hash (see {@link #PLACEHOLDER}),
 * e.g.
 * {@code https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}}.
 * This is deliberately not derived from a bare base URL: the REST path and
 * any extra filters (e.g. Artifactory's {@code repos} parameter) are under
 * JFrog's control, and hardcoding them here could go stale. Requiring the
 * full URL means an Artifactory-side API change only needs a config update,
 * not a new plugin release.
 * </p>
 */
final class ArtifactoryChecksumLookup implements ChecksumArtifactLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;
    private final String basicAuthHeader;

    ArtifactoryChecksumLookup(HttpClient client, Duration timeout, String searchUrlTemplate, String basicAuthHeader) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
        this.basicAuthHeader = basicAuthHeader;
    }

    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        URI uri = URI.create(searchUrlTemplate.replace(PLACEHOLDER, sha1Hex));
        return HttpChecksumLookupSupport.get(client, uri, timeout, basicAuthHeader)
                .flatMap(body -> MinimalJson.firstArrayObject(body, "results"))
                .flatMap(result -> MinimalJson.stringField(result, "uri"))
                .flatMap(ArtifactoryChecksumLookup::toCoords);
    }

    /**
     * Recovers {@code groupId:artifactId:version} from a storage {@code uri}
     * following the standard Maven2 layout, anchored at the {@code storage}
     * path segment that precedes the repository key.
     *
     * @return the coordinates, or empty if the path does not follow the
     *         expected shape (e.g. a non-Maven-layout repository)
     */
    private static Optional<ArtifactCoords> toCoords(String uri) {
        String path = URI.create(uri).getPath();
        if (path == null) {
            return Optional.empty();
        }
        List<String> segments = new ArrayList<>();
        for (String segment : path.split("/")) {
            if (!segment.isEmpty()) {
                segments.add(segment);
            }
        }
        int storageIdx = segments.lastIndexOf("storage");
        if (storageIdx < 0) {
            return Optional.empty();
        }
        // segments after "storage": [repoKey, g1, g2, ..., artifactId, version, file]
        List<String> repoRelative = segments.subList(storageIdx + 1, segments.size());
        if (repoRelative.size() < 4) {
            return Optional.empty();
        }
        int size = repoRelative.size();
        String version = repoRelative.get(size - 2);
        String artifactId = repoRelative.get(size - 3);
        List<String> groupPath = repoRelative.subList(1, size - 3);
        if (groupPath.isEmpty()) {
            return Optional.empty();
        }
        String groupId = String.join(".", groupPath);
        return Optional.of(ArtifactCoords.of(groupId, artifactId, version));
    }
}
