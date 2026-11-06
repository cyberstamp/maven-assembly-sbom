package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpServer;

class RemoteChecksumResolverTest {

    @TempDir
    Path tempDir;

    private HttpServer nexusServer;
    private HttpServer artifactoryServer;

    @AfterEach
    void stopServers() {
        if (nexusServer != null) {
            nexusServer.stop(0);
        }
        if (artifactoryServer != null) {
            artifactoryServer.stop(0);
        }
    }

    @Test
    void disabledConfigYieldsEmptyResolver() {
        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(false);

        assertTrue(RemoteChecksumResolver.create(config, null, null, null, null).isEmpty());
    }

    @Test
    void enabledWithoutIncludesYieldsEmptyResolver() {
        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);

        assertTrue(RemoteChecksumResolver.create(config, null, null, null, null).isEmpty());
    }

    @Test
    void enabledWithoutAnyBackendYieldsEmptyResolver() {
        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);
        config.setIncludes(List.of("**/*.jar"));
        config.setCentral(false);

        assertTrue(RemoteChecksumResolver.create(config, null, null, null, null).isEmpty());
    }

    @Test
    void isCandidateHonorsIncludesAndExcludes() {
        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);
        config.setIncludes(List.of("**/*.jar"));
        config.setExcludes(List.of("**/test-*.jar"));

        RemoteChecksumResolver resolver = RemoteChecksumResolver.create(config, null, null, null, null).orElseThrow();

        assertTrue(resolver.isCandidate("lib/foo.jar"));
        assertFalse(resolver.isCandidate("lib/test-foo.jar"));
        assertFalse(resolver.isCandidate("lib/foo.txt"));
    }

    @Test
    void fallsBackToSecondBackendWhenFirstHasNoMatch() throws IOException {
        AtomicInteger nexusHits = new AtomicInteger();
        AtomicInteger artifactoryHits = new AtomicInteger();
        nexusServer = startServer("/service/rest/v1/search", nexusHits, "{\"items\":[]}");
        artifactoryServer = startServer("/api/search/checksum", artifactoryHits,
                "{\"results\":[{\"uri\":\"http://x/api/storage/repo/com/example/lib/1.0/lib-1.0.jar\"}]}");

        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);
        config.setCentral(false);
        config.setIncludes(List.of("**/*.jar"));
        config.setNexusUrl("http://127.0.0.1:" + nexusServer.getAddress().getPort());
        config.setArtifactoryUrl("http://127.0.0.1:" + artifactoryServer.getAddress().getPort());

        RemoteChecksumResolver resolver = RemoteChecksumResolver.create(config, null, null, null, null).orElseThrow();
        FileEntry entry = fileEntry("lib/lib.jar", "content-a");

        Optional<ArtifactCoords> result = resolver.resolve(entry);

        assertEquals(Optional.of(ArtifactCoords.of("com.example", "lib", "1.0")), result);
        assertEquals(1, nexusHits.get());
        assertEquals(1, artifactoryHits.get());
    }

    @Test
    void cachesResultPerSha1() throws IOException {
        AtomicInteger hits = new AtomicInteger();
        nexusServer = startServer("/service/rest/v1/search", hits,
                "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"1.0\"}]}");

        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);
        config.setCentral(false);
        config.setIncludes(List.of("**/*.jar"));
        config.setNexusUrl("http://127.0.0.1:" + nexusServer.getAddress().getPort());

        RemoteChecksumResolver resolver = RemoteChecksumResolver.create(config, null, null, null, null).orElseThrow();
        FileEntry first = fileEntry("lib/a.jar", "same-content");
        FileEntry second = fileEntry("lib/b.jar", "same-content");

        resolver.resolve(first);
        resolver.resolve(second);

        assertEquals(1, hits.get(), "second lookup of an identical-content file should hit the cache, not the network");
    }

    @Test
    void stopsCallingBackendsOnceMaxLookupsIsExhausted() throws IOException {
        AtomicInteger hits = new AtomicInteger();
        nexusServer = startServer("/service/rest/v1/search", hits, "{\"items\":[]}");

        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);
        config.setCentral(false);
        config.setIncludes(List.of("**/*.jar"));
        config.setNexusUrl("http://127.0.0.1:" + nexusServer.getAddress().getPort());
        config.setMaxLookups(1);

        RemoteChecksumResolver resolver = RemoteChecksumResolver.create(config, null, null, null, null).orElseThrow();

        resolver.resolve(fileEntry("lib/a.jar", "content-a"));
        resolver.resolve(fileEntry("lib/b.jar", "content-b"));

        assertEquals(1, hits.get(), "no backend call should be made once the lookup budget is exhausted");
    }

    private HttpServer startServer(String path, AtomicInteger hits, String body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(path, exchange -> {
            hits.incrementAndGet();
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return server;
    }

    private FileEntry fileEntry(String archivePath, String content) throws IOException {
        Path file = tempDir.resolve(archivePath.replace('/', '_') + "-" + content.hashCode());
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return new FileEntry(archivePath, "unused", file.toFile());
    }
}
