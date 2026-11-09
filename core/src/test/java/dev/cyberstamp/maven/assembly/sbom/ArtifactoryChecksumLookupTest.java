package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

class ArtifactoryChecksumLookupTest {

    private HttpServer server;
    private final AtomicReference<String> lastAuthHeader = new AtomicReference<>();
    private final AtomicReference<String> lastQuery = new AtomicReference<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private void respondWith(int status, String body) {
        server.createContext("/api/search/checksum", exchange -> {
            lastAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            lastQuery.set(exchange.getRequestURI().getQuery());
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    @Test
    void substitutesSha1IntoConfiguredSearchUrlAndKeepsExtraParameters() {
        respondWith(200, "{\"results\":[{\"uri\":\"https://artifactory.example.com/artifactory/api/storage/"
                + "libs-release-local/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar\"}]}");
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        String searchUrl = baseUrl + "/api/search/checksum?sha1=" + ArtifactoryChecksumLookup.PLACEHOLDER
                + "&repos=central,my-internal-repo";
        ArtifactoryChecksumLookup artifactory = new ArtifactoryChecksumLookup(
                HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, null);

        Optional<ArtifactCoords> result = artifactory.lookup("abc123");

        assertEquals(Optional.of(ArtifactCoords.of("org.apache.commons", "commons-lang3", "3.12.0")), result);
        assertEquals("sha1=abc123&repos=central,my-internal-repo", lastQuery.get());
    }

    @Test
    void recoversCoordsFromStandardMaven2LayoutUri() {
        respondWith(200, "{\"results\":[{\"uri\":\"https://artifactory.example.com/artifactory/api/storage/"
                + "libs-release-local/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar\"}]}");

        Optional<ArtifactCoords> result = lookup(null).lookup("abc123");

        assertEquals(Optional.of(ArtifactCoords.of("org.apache.commons", "commons-lang3", "3.12.0")), result);
    }

    @Test
    void sendsAuthorizationHeaderWhenConfigured() {
        respondWith(200, "{\"results\":[]}");
        String auth = HttpChecksumLookupSupport.basicAuthHeader("bob", "hunter2");

        lookup(auth).lookup("abc123");

        assertEquals(auth, lastAuthHeader.get());
    }

    @Test
    void returnsEmptyWhenNoResultsFound() {
        respondWith(200, "{\"results\":[]}");

        assertTrue(lookup(null).lookup("deadbeef").isEmpty());
    }

    @Test
    void returnsEmptyWhenUriDoesNotFollowMaven2Layout() {
        respondWith(200, "{\"results\":[{\"uri\":\"https://artifactory.example.com/artifactory/"
                + "some-generic-repo/not-a-maven-path.bin\"}]}");

        assertTrue(lookup(null).lookup("abc123").isEmpty());
    }

    @Test
    void returnsEmptyOnNon200Status() {
        respondWith(401, "");

        assertTrue(lookup(null).lookup("abc123").isEmpty());
    }

    @Test
    void returnsEmptyWhenServerUnreachable() {
        ArtifactoryChecksumLookup artifactory = new ArtifactoryChecksumLookup(HttpClient.newHttpClient(),
                Duration.ofMillis(500),
                "http://127.0.0.1:1/api/search/checksum?sha1=" + ArtifactoryChecksumLookup.PLACEHOLDER, null);

        assertTrue(artifactory.lookup("abc123").isEmpty());
    }

    private ArtifactoryChecksumLookup lookup(String authHeader) {
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        String searchUrl = baseUrl + "/api/search/checksum?sha1=" + ArtifactoryChecksumLookup.PLACEHOLDER;
        return new ArtifactoryChecksumLookup(HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, authHeader);
    }
}
