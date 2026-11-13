package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

class ArtifactoryCoordinatesLookupTest {

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
        String searchUrl = baseUrl + "/api/search/checksum?sha1=" + ArtifactoryCoordinatesLookup.PLACEHOLDER
                + "&repos=central,my-internal-repo";
        ArtifactoryCoordinatesLookup artifactory = new ArtifactoryCoordinatesLookup(
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
        String auth = HttpLookupSupport.basicAuthHeader("bob", "hunter2");

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
    void returnsEmptyWhenServerUnreachable() throws IOException {
        ArtifactoryCoordinatesLookup artifactory = new ArtifactoryCoordinatesLookup(HttpClient.newHttpClient(),
                Duration.ofMillis(500),
                "http://127.0.0.1:" + unreachablePort() + "/api/search/checksum?sha1="
                        + ArtifactoryCoordinatesLookup.PLACEHOLDER,
                null);

        assertTrue(artifactory.lookup("abc123").isEmpty());
    }

    private ArtifactoryCoordinatesLookup lookup(String authHeader) {
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        String searchUrl = baseUrl + "/api/search/checksum?sha1=" + ArtifactoryCoordinatesLookup.PLACEHOLDER;
        return new ArtifactoryCoordinatesLookup(HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, authHeader);
    }

    /**
     * Returns a loopback port nothing is listening on, by briefly binding
     * one and releasing it.
     */
    private static int unreachablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }
}
