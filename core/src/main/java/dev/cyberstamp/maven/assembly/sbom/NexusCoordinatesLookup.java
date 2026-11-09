package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

/**
 * Looks up Maven coordinates by SHA-1 against an internal Nexus Repository
 * Manager 3 instance, using its REST search API.
 *
 * <p>
 * Targets Nexus 3 only; Nexus 2 (whose search API differs) has reached
 * end-of-life and is out of scope. The response is expected in Nexus 3's
 * search-result shape: a top-level {@code items} array, each with
 * {@code group}/{@code name}/{@code version} fields.
 * </p>
 *
 * <p>
 * The configured URL must be a complete search request containing a literal
 * {@code {sha1}} placeholder for the content hash (see {@link #PLACEHOLDER}),
 * e.g. {@code https://nexus.example.com/service/rest/v1/search?sha1={sha1}}.
 * This is deliberately not derived from a bare base URL: the REST path and
 * any extra filters (e.g. Nexus's {@code repository} parameter) are under
 * Sonatype's control, and hardcoding them here could go stale. Requiring the
 * full URL means a Nexus-side API change only needs a config update, not a
 * new plugin release.
 * </p>
 */
final class NexusCoordinatesLookup implements CoordinatesLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;
    private final String basicAuthHeader;

    NexusCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate, String basicAuthHeader) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
        this.basicAuthHeader = basicAuthHeader;
    }

    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        URI uri = URI.create(searchUrlTemplate.replace(PLACEHOLDER, sha1Hex));
        return HttpLookupSupport.get(client, uri, timeout, basicAuthHeader)
                .flatMap(body -> MinimalJson.firstArrayObject(body, "items"))
                .flatMap(NexusCoordinatesLookup::toCoords);
    }

    private static Optional<ArtifactCoords> toCoords(String item) {
        Optional<String> groupId = MinimalJson.stringField(item, "group");
        Optional<String> artifactId = MinimalJson.stringField(item, "name");
        Optional<String> version = MinimalJson.stringField(item, "version");
        if (groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(ArtifactCoords.of(groupId.get(), artifactId.get(), version.get()));
    }
}
