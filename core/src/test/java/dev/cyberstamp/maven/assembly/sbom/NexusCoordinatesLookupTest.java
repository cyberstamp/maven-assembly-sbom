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

class NexusCoordinatesLookupTest {

    private HttpServer server;
    private final AtomicReference<String> lastQuery = new AtomicReference<>();
    private final AtomicReference<String> lastAuthHeader = new AtomicReference<>();

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
        server.createContext("/service/rest/v1/search", exchange -> {
            lastQuery.set(exchange.getRequestURI().getQuery());
            lastAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    @Test
    void returnsCoordsOnMatch() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\"}],"
                + "\"continuationToken\":null}");

        Optional<ArtifactCoords> result = lookup(null).lookup("abc123");

        assertEquals(Optional.of(ArtifactCoords.of("com.example", "lib", "2.0")), result);
        assertEquals("sha1=abc123", lastQuery.get());
    }

    @Test
    void sendsAuthorizationHeaderWhenConfigured() {
        respondWith(200, "{\"items\":[]}");
        String auth = HttpLookupSupport.basicAuthHeader("alice", "s3cr3t");

        lookup(auth).lookup("abc123");

        assertEquals(auth, lastAuthHeader.get());
    }

    @Test
    void sendsNoAuthorizationHeaderWhenAnonymous() {
        respondWith(200, "{\"items\":[]}");

        lookup(null).lookup("abc123");

        assertNull(lastAuthHeader.get());
    }

    @Test
    void returnsEmptyWhenNoItemsFound() {
        respondWith(200, "{\"items\":[]}");

        assertTrue(lookup(null).lookup("deadbeef").isEmpty());
    }

    @Test
    void returnsEmptyOnNon200Status() {
        respondWith(403, "");

        assertTrue(lookup(null).lookup("abc123").isEmpty());
    }

    @Test
    void returnsEmptyWhenServerUnreachable() {
        NexusCoordinatesLookup nexus = new NexusCoordinatesLookup(HttpClient.newHttpClient(), Duration.ofMillis(500),
                "http://127.0.0.1:1/service/rest/v1/search?sha1=" + NexusCoordinatesLookup.PLACEHOLDER, null);

        assertTrue(nexus.lookup("abc123").isEmpty());
    }

    @Test
    void substitutesSha1IntoConfiguredSearchUrlAndKeepsExtraParameters() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\"}]}");
        String searchUrl = baseUrl() + "/service/rest/v1/search?sha1=" + NexusCoordinatesLookup.PLACEHOLDER
                + "&repository=my-repo";
        NexusCoordinatesLookup nexus = new NexusCoordinatesLookup(
                HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, null);

        Optional<ArtifactCoords> result = nexus.lookup("abc123");

        assertEquals(Optional.of(ArtifactCoords.of("com.example", "lib", "2.0")), result);
        assertEquals("sha1=abc123&repository=my-repo", lastQuery.get());
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private NexusCoordinatesLookup lookup(String authHeader) {
        String searchUrl = baseUrl() + "/service/rest/v1/search?sha1=" + NexusCoordinatesLookup.PLACEHOLDER;
        return new NexusCoordinatesLookup(HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, authHeader);
    }
}
