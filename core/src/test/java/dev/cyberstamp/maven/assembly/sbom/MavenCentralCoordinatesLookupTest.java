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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

/**
 * Exercises {@link MavenCentralCoordinatesLookup} against an in-process stub
 * HTTP server (JDK built-in, no new test dependency) serving canned Solr
 * search responses, since the real {@code search.maven.org} endpoint is not
 * reachable in a unit test.
 */
class MavenCentralCoordinatesLookupTest {

    private HttpServer server;
    private volatile String lastQuery;

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
        server.createContext("/solrsearch/select", exchange -> {
            lastQuery = exchange.getRequestURI().getQuery();
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    @Test
    void returnsCoordsOnMatch() {
        respondWith(200, "{\"response\":{\"docs\":[{\"g\":\"org.example\",\"a\":\"lib\",\"v\":\"1.0\"}]}}");

        Optional<ArtifactCoords> result = lookup().lookup("abc123");

        assertEquals(Optional.of(ArtifactCoords.of("org.example", "lib", "1.0")), result);
        assertTrue(lastQuery.contains("q=1:abc123"));
    }

    @Test
    void returnsEmptyWhenNoDocsFound() {
        respondWith(200, "{\"response\":{\"numFound\":0,\"docs\":[]}}");

        assertTrue(lookup().lookup("deadbeef").isEmpty());
    }

    @Test
    void returnsEmptyOnNon200Status() {
        respondWith(500, "");

        assertTrue(lookup().lookup("abc123").isEmpty());
    }

    @Test
    void returnsEmptyWhenServerUnreachable() throws IOException {
        MavenCentralCoordinatesLookup central = new MavenCentralCoordinatesLookup(
                HttpClient.newHttpClient(), Duration.ofMillis(500),
                "http://127.0.0.1:" + unreachablePort() + "/solrsearch/select?q=1:%s&rows=1&wt=json");

        assertTrue(central.lookup("abc123").isEmpty());
    }

    private MavenCentralCoordinatesLookup lookup() {
        String template = "http://127.0.0.1:" + server.getAddress().getPort()
                + "/solrsearch/select?q=1:%s&rows=1&wt=json";
        return new MavenCentralCoordinatesLookup(HttpClient.newHttpClient(), Duration.ofSeconds(5), template);
    }

    /**
     * Returns a loopback port nothing is listening on, by briefly binding
     * one and releasing it. Deliberately not a low-numbered port like
     * {@code 1}: those are "privileged" on Linux (require root to bind to),
     * and some sandboxed/firewalled environments handle connection attempts
     * to them differently (e.g. silently dropping instead of refusing),
     * which could make this test flaky or slow depending on where it runs.
     */
    private static int unreachablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }
}
