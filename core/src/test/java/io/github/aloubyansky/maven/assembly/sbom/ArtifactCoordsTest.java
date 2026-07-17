package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ArtifactCoordsTest {

    @Test
    void toStringWithoutClassifier() {
        ArtifactCoords id = ArtifactCoords.of("org.example", "foo", "1.0");
        assertEquals("org.example:foo:1.0", id.toString());
    }

    @Test
    void toStringWithClassifier() {
        ArtifactCoords id = new ArtifactCoords("org.example", "foo", "1.0", "jar", "linux-x86_64");
        assertEquals("org.example:foo:1.0:linux-x86_64", id.toString());
    }

    @Test
    void toStringWithNonJarType() {
        ArtifactCoords id = new ArtifactCoords("org.example", "foo", "1.0", "war", null);
        assertEquals("org.example:foo:war:1.0", id.toString());
    }

    @Test
    void toStringWithNonJarTypeAndClassifier() {
        ArtifactCoords id = new ArtifactCoords("org.example", "foo", "1.0", "war", "classes");
        assertEquals("org.example:foo:war:1.0:classes", id.toString());
    }

    @Test
    void emptyClassifierNormalizedToNull() {
        ArtifactCoords withEmpty = new ArtifactCoords("org.example", "foo", "1.0", null, "");
        ArtifactCoords withNull = new ArtifactCoords("org.example", "foo", "1.0", null, null);
        assertEquals(withNull, withEmpty);
        assertNull(withEmpty.classifier());
        assertEquals(withNull.hashCode(), withEmpty.hashCode());
    }

    @Test
    void toGavOmitsClassifier() {
        ArtifactCoords id = new ArtifactCoords("org.example", "foo", "1.0", "jar", "linux-x86_64");
        assertEquals("org.example:foo:1.0", id.toGav());
    }

    @Test
    void toGavSameAsToStringWhenNoClassifier() {
        ArtifactCoords id = ArtifactCoords.of("org.example", "foo", "1.0");
        assertEquals(id.toGav(), id.toString());
    }

    @Test
    void fromMavenArtifact() {
        DefaultArtifact artifact = new DefaultArtifact(
                "org.example", "bar", "2.0", "compile", "jar", null,
                new DefaultArtifactHandler("jar"));
        ArtifactCoords id = ArtifactCoords.of(artifact);
        assertEquals("org.example", id.groupId());
        assertEquals("bar", id.artifactId());
        assertEquals("2.0", id.version());
        assertEquals("jar", id.type());
        assertNull(id.classifier());
    }

    @Test
    void fromMavenArtifactWithClassifier() {
        DefaultArtifact artifact = new DefaultArtifact(
                "org.example", "bar", "2.0", "compile", "jar", "linux-x86_64",
                new DefaultArtifactHandler("jar"));
        ArtifactCoords id = ArtifactCoords.of(artifact);
        assertEquals("linux-x86_64", id.classifier());
        assertEquals("org.example:bar:2.0:linux-x86_64", id.toString());
    }

    @Test
    void fromAetherArtifact() {
        org.eclipse.aether.artifact.DefaultArtifact artifact = new org.eclipse.aether.artifact.DefaultArtifact(
                "org.example", "baz", "javadoc", "jar", "3.0");
        ArtifactCoords id = ArtifactCoords.of(artifact);
        assertEquals("org.example", id.groupId());
        assertEquals("baz", id.artifactId());
        assertEquals("3.0", id.version());
        assertEquals("javadoc", id.type());
        assertNull(id.classifier());
    }

    @Test
    void equalityByFields() {
        ArtifactCoords a = new ArtifactCoords("org.example", "foo", "1.0", "jar", "linux-x86_64");
        ArtifactCoords b = new ArtifactCoords("org.example", "foo", "1.0", "jar", "linux-x86_64");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void differentClassifierNotEqual() {
        ArtifactCoords a = ArtifactCoords.of("org.example", "foo", "1.0");
        ArtifactCoords b = new ArtifactCoords("org.example", "foo", "1.0", "jar", "linux-x86_64");
        assertNotEquals(a, b);
    }

    @Test
    void differentVersionNotEqual() {
        ArtifactCoords a = ArtifactCoords.of("org.example", "foo", "1.0");
        ArtifactCoords b = ArtifactCoords.of("org.example", "foo", "2.0");
        assertNotEquals(a, b);
    }

    @Test
    void nullGroupIdThrows() {
        assertThrows(NullPointerException.class,
                () -> new ArtifactCoords(null, "foo", "1.0", null, null));
    }

    @Test
    void nullArtifactIdThrows() {
        assertThrows(NullPointerException.class,
                () -> new ArtifactCoords("org.example", null, "1.0", null, null));
    }

    @Test
    void nullVersionThrows() {
        assertThrows(NullPointerException.class,
                () -> new ArtifactCoords("org.example", "foo", null, null, null));
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void handlerClassifierTypesNormalizedFromMaven(String mavenType, String handlerClassifier) {
        DefaultArtifact artifact = new DefaultArtifact(
                "org.example", "bar", "2.0", "compile", mavenType, handlerClassifier,
                new DefaultArtifactHandler(mavenType));
        ArtifactCoords id = ArtifactCoords.of(artifact);
        assertEquals(mavenType, id.type());
        assertNull(id.classifier());
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void handlerClassifierTypesNormalizedFromAether(String mavenType, String handlerClassifier) {
        // Aether represents these as extension="jar" + the handler classifier
        org.eclipse.aether.artifact.DefaultArtifact artifact = new org.eclipse.aether.artifact.DefaultArtifact(
                "org.example", "bar", handlerClassifier, "jar", "2.0");
        ArtifactCoords id = ArtifactCoords.of(artifact);
        assertEquals(mavenType, id.type());
        assertNull(id.classifier());
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void handlerClassifierTypesMavenEqualsAether(String mavenType, String handlerClassifier) {
        DefaultArtifact mavenArtifact = new DefaultArtifact(
                "org.example", "bar", "2.0", "compile", mavenType, handlerClassifier,
                new DefaultArtifactHandler(mavenType));
        ArtifactCoords fromMaven = ArtifactCoords.of(mavenArtifact);

        org.eclipse.aether.artifact.DefaultArtifact aetherArtifact = new org.eclipse.aether.artifact.DefaultArtifact(
                "org.example", "bar", handlerClassifier, "jar", "2.0");
        ArtifactCoords fromAether = ArtifactCoords.of(aetherArtifact);

        assertEquals(fromMaven, fromAether);
    }

    @ParameterizedTest
    @CsvSource({
            "test-jar,  tests",
            "ejb-client, client",
            "java-source, sources",
            "javadoc,   javadoc"
    })
    void handlerClassifierTypesNormalizedFromConstructor(String mavenType, String handlerClassifier) {
        // direct constructor with extension "jar" + handler classifier
        ArtifactCoords fromExtension = new ArtifactCoords(
                "org.example", "bar", "2.0", "jar", handlerClassifier);
        // direct constructor with Maven type + handler classifier
        ArtifactCoords fromType = new ArtifactCoords(
                "org.example", "bar", "2.0", mavenType, handlerClassifier);

        assertEquals(fromExtension, fromType);
        assertEquals(mavenType, fromExtension.type());
        assertNull(fromExtension.classifier());
    }
}
