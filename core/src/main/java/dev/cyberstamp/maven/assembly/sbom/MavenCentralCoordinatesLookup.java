package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

/**
 * Looks up Maven coordinates by SHA-1 against the public Maven Central
 * search API ({@code search.maven.org}) by default. Requires no
 * configuration or credentials, but the search URL can be overridden (see
 * {@link RemoteArtifactLookup#setCentralUrl(String)}) — e.g. to point at an
 * internal mirror of the Central search API, or to adapt if Sonatype ever
 * changes its public API shape, without needing a new plugin release.
 */
final class MavenCentralCoordinatesLookup implements CoordinatesLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    static final String DEFAULT_SEARCH_URL = "https://search.maven.org/solrsearch/select?q=1:"
            + PLACEHOLDER + "&rows=1&wt=json";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;

    MavenCentralCoordinatesLookup(HttpClient client, Duration timeout) {
        this(client, timeout, DEFAULT_SEARCH_URL);
    }

    /**
     * @param searchUrlTemplate a complete search URL containing a literal
     *        {@code {sha1}} placeholder for the content hash; overridable so
     *        tests can point at a stub server instead of the real API
     */
    MavenCentralCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
    }

    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        URI uri = URI.create(searchUrlTemplate.replace(PLACEHOLDER, sha1Hex));
        return HttpLookupSupport.get(client, uri, timeout, null)
                .flatMap(body -> JsonLookupSupport.firstArrayObject(body, "docs"))
                .flatMap(MavenCentralCoordinatesLookup::toCoords);
    }

    private static Optional<ArtifactCoords> toCoords(String doc) {
        Optional<String> groupId = JsonLookupSupport.stringField(doc, "g");
        Optional<String> artifactId = JsonLookupSupport.stringField(doc, "a");
        Optional<String> version = JsonLookupSupport.stringField(doc, "v");
        if (groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(ArtifactCoords.of(groupId.get(), artifactId.get(), version.get()));
    }
}
