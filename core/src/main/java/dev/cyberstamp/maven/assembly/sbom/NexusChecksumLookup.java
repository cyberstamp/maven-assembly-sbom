package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

/**
 * Looks up Maven coordinates by SHA-1 against an internal Nexus Repository
 * Manager 3 instance, using its REST search API
 * ({@code GET /service/rest/v1/search?sha1=...}).
 *
 * <p>
 * Targets Nexus 3 only; Nexus 2 (whose search API differs) has reached
 * end-of-life and is out of scope.
 * </p>
 */
final class NexusChecksumLookup implements ChecksumArtifactLookup {

    private final HttpClient client;
    private final Duration timeout;
    private final String baseUrl;
    private final String basicAuthHeader;

    NexusChecksumLookup(HttpClient client, Duration timeout, String baseUrl, String basicAuthHeader) {
        this.client = client;
        this.timeout = timeout;
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.basicAuthHeader = basicAuthHeader;
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        URI uri = URI.create(baseUrl + "/service/rest/v1/search?sha1=" + sha1Hex);
        return HttpChecksumLookupSupport.get(client, uri, timeout, basicAuthHeader)
                .flatMap(body -> MinimalJson.firstArrayObject(body, "items"))
                .flatMap(NexusChecksumLookup::toCoords);
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
