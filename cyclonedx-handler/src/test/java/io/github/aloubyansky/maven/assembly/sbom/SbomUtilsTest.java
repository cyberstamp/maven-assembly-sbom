package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Date;

import org.eclipse.aether.artifact.DefaultArtifact;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SbomUtilsTest {

    @TempDir
    Path tempDir;

    // ---- parseBuildTimestamp ----

    @Test
    void parseBuildTimestamp_null_returnsNull() {
        assertNull(SbomUtils.parseBuildTimestamp(null));
    }

    @Test
    void parseBuildTimestamp_blank_returnsNull() {
        assertNull(SbomUtils.parseBuildTimestamp("  "));
    }

    @Test
    void parseBuildTimestamp_iso8601() {
        Date result = SbomUtils.parseBuildTimestamp("2024-01-15T10:30:00Z");
        assertNotNull(result);
        assertEquals(1705314600000L, result.getTime());
    }

    @Test
    void parseBuildTimestamp_epochSeconds() {
        Date result = SbomUtils.parseBuildTimestamp("1705314600");
        assertNotNull(result);
        assertEquals(1705314600000L, result.getTime());
    }

    @Test
    void parseBuildTimestamp_dateOnly() {
        Date result = SbomUtils.parseBuildTimestamp("2024-01-15");
        assertNotNull(result);
        assertEquals(1705276800000L, result.getTime());
    }

    @Test
    void parseBuildTimestamp_zero_returnsNull() {
        assertNull(SbomUtils.parseBuildTimestamp("0"));
    }

    @Test
    void parseBuildTimestamp_invalid_returnsNull() {
        assertNull(SbomUtils.parseBuildTimestamp("not-a-date"));
    }

    // ---- computeHash ----

    @Test
    void computeHash_stream() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = "hello world".getBytes(StandardCharsets.UTF_8);
        String hash = SbomUtils.computeHash(digest, new ByteArrayInputStream(content));

        assertNotNull(hash);
        assertEquals(64, hash.length());
        assertEquals("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash);
    }

    // ---- toAetherArtifact ----

    @Test
    void toAetherArtifact_plainJar() {
        DefaultArtifact result = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", "jar", null);
        assertEquals("jar", result.getExtension());
        assertEquals("", result.getClassifier());
    }

    @Test
    void toAetherArtifact_nullTypeDefaultsToJar() {
        DefaultArtifact result = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", null, null);
        assertEquals("jar", result.getExtension());
    }

    @Test
    void toAetherArtifact_war() {
        DefaultArtifact result = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", "war", null);
        assertEquals("war", result.getExtension());
        assertEquals("", result.getClassifier());
    }

    @Test
    void toAetherArtifact_jarWithExplicitClassifier() {
        DefaultArtifact result = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", "jar", "linux-x86_64");
        assertEquals("jar", result.getExtension());
        assertEquals("linux-x86_64", result.getClassifier());
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void toAetherArtifact_handlerClassifiedTypeWithNoClassifier(
            String mavenType, String expectedClassifier) {
        DefaultArtifact result = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", mavenType, null);
        assertEquals("jar", result.getExtension());
        assertEquals(expectedClassifier, result.getClassifier());
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void toAetherArtifact_handlerClassifiedTypeWithHandlerClassifier(
            String mavenType, String handlerClassifier) {
        DefaultArtifact result = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", mavenType, handlerClassifier);
        assertEquals("jar", result.getExtension());
        assertEquals(handlerClassifier, result.getClassifier());
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void toAetherArtifact_roundTripWithArtifactCoords(
            String mavenType, String handlerClassifier) {
        DefaultArtifact aether = SbomUtils.toAetherArtifact(
                "org.example", "foo", "1.0", mavenType, null);
        ArtifactCoords coords = ArtifactCoords.of(aether);
        assertEquals(mavenType, coords.type());
        assertNull(coords.classifier());
    }

    @Test
    void computeHash_path() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Path file = tempDir.resolve("test.txt");
        Files.writeString(file, "hello world");

        String hash = SbomUtils.computeHash(digest, file);
        assertEquals("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash);
    }

}
