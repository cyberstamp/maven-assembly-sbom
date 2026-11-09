package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

/**
 * Looks up Maven coordinates by SHA-1 against the public Maven Central
 * search API ({@code search.maven.org}). Requires no configuration or
 * credentials.
 */
final class MavenCentralCoordinatesLookup implements CoordinatesLookup {

    private static final String DEFAULT_SEARCH_URL_TEMPLATE = "https://search.maven.org/solrsearch/select?q=1:%s&rows=1&wt=json";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;

    MavenCentralCoordinatesLookup(HttpClient client, Duration timeout) {
        this(client, timeout, DEFAULT_SEARCH_URL_TEMPLATE);
    }

    /**
     * @param searchUrlTemplate a {@code String.format} template with a single
     *        {@code %s} placeholder for the SHA-1 hex digest; overridable so
     *        tests can point at a stub server instead of the real API
     */
    MavenCentralCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
    }

    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        URI uri = URI.create(String.format(searchUrlTemplate, sha1Hex));
        return HttpLookupSupport.get(client, uri, timeout, null)
                .flatMap(body -> MinimalJson.firstArrayObject(body, "docs"))
                .flatMap(MavenCentralCoordinatesLookup::toCoords);
    }

    private static Optional<ArtifactCoords> toCoords(String doc) {
        Optional<String> groupId = MinimalJson.stringField(doc, "g");
        Optional<String> artifactId = MinimalJson.stringField(doc, "a");
        Optional<String> version = MinimalJson.stringField(doc, "v");
        if (groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(ArtifactCoords.of(groupId.get(), artifactId.get(), version.get()));
    }
}
