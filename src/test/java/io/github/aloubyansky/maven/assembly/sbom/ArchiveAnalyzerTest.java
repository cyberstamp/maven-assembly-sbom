package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ArchiveAnalyzerTest {

    @TempDir
    Path tempDir;

    @Mock
    EffectiveModelResolver effectiveModelResolver;

    @Mock
    RepositorySystem repoSystem;

    @Mock
    MavenProject project;

    @Mock
    MavenSession session;

    private MessageDigest digest;

    @BeforeEach
    void setUp() throws Exception {
        digest = MessageDigest.getInstance("SHA-256");
        lenient().when(session.getProjects()).thenReturn(List.of());
    }

    @Test
    void matchedArtifactClassifiedAsMavenEntry() throws Exception {
        Path jarFile = createTestJar("lib-a-1.0.jar", "content-a");
        Artifact artifact = createArtifact("org.example", "lib-a", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, jarFile);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("lib/lib-a-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size());
        assertEquals(0, content.unmatchedFiles().size());
        assertEquals("org.example", content.mavenEntries().get(0).artifactId().groupId());
        assertEquals("lib/lib-a-1.0.jar", content.mavenEntries().get(0).archivePath());
    }

    @Test
    void topLevelShadedJarDetectsBundledDeps() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("nimbus-jose-jwt-10.9.1.jar",
                "com.nimbusds", "nimbus-jose-jwt", "10.9.1",
                "com.github.stephenc.jcip", "jcip-annotations", "1.0-1",
                "nimbus-content");
        Artifact artifact = createArtifact("com.nimbusds", "nimbus-jose-jwt", "10.9.1", "jar",
                shadedJar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("lib/nimbus-jose-jwt-10.9.1.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size());
        assertEquals("nimbus-jose-jwt", content.mavenEntries().get(0).artifactId().artifactId());
        var bundledEntry = content.nestedEntries().stream()
                .filter(e -> "jcip-annotations".equals(e.artifactId().artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry,
                "bundled dep should be detected in top-level shaded JAR");
        assertEquals("nimbus-jose-jwt", bundledEntry.parentId().artifactId(),
                "bundled dep parent should be the shaded JAR");
    }

    @Test
    void unmatchedFileClassifiedCorrectly() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest,
                new java.io.ByteArrayInputStream("config-data".getBytes(StandardCharsets.UTF_8)));
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("conf/app.properties", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(0, content.mavenEntries().size());
        assertEquals(1, content.unmatchedFiles().size());
        assertEquals("conf/app.properties", content.unmatchedFiles().get(0).path());
    }

    @Test
    void baseDirPrefixStripped() throws Exception {
        Path jarFile = createTestJar("lib-a-1.0.jar", "content-strip");
        Artifact artifact = createArtifact("org.example", "lib-a", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, jarFile);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("myapp-1.0/lib/lib-a-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, "myapp-1.0/");

        assertEquals(1, content.mavenEntries().size());
        assertEquals("lib/lib-a-1.0.jar", content.mavenEntries().get(0).archivePath());
    }

    @Test
    void unpackedArtifactDetectedByContentHash() throws Exception {
        Path entryFile = createTestFile("entry.txt", "unpacked-entry-data");
        byte[] entryBytes = Files.readAllBytes(entryFile);

        Path warFile = tempDir.resolve("mywar-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/entry.txt"));
            jos.write(entryBytes);
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "mywar", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String entryHash = SbomUtils.computeHash(digest, entryFile);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/entry.txt", entryHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size());
        assertEquals("mywar", content.mavenEntries().get(0).artifactId().artifactId());
        assertEquals(1, content.unmatchedFiles().size(),
                "non-identifiable nested file should be preserved as unmatched");
    }

    @Test
    void nestedJarIdentifiedViaPomProperties() throws Exception {
        Path nestedJar = createJarWithPomProperties("nested-1.0.jar",
                "org.nested", "nested", "1.0", "nested-content");

        Path warFile = tempDir.resolve("parent-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/nested-1.0.jar"));
            jos.write(Files.readAllBytes(nestedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "parent", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String nestedHash = SbomUtils.computeHash(digest, nestedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/parent/WEB-INF/lib/nested-1.0.jar", nestedHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "parent WAR should be matched");
        assertEquals(1, content.nestedEntries().size(), "nested JAR should be identified");
        assertEquals("nested", content.nestedEntries().get(0).artifactId().artifactId());
        assertEquals("org.nested", content.nestedEntries().get(0).artifactId().groupId());
    }

    @Test
    void multipleEntriesMixedClassification() throws Exception {
        Path jarFile = createTestJar("known-1.0.jar", "known-content");
        Artifact artifact = createArtifact("org.example", "known", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String knownHash = SbomUtils.computeHash(digest, jarFile);
        String unknownHash = SbomUtils.computeHash(digest,
                new java.io.ByteArrayInputStream("unknown-content".getBytes(StandardCharsets.UTF_8)));

        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("lib/known-1.0.jar", knownHash),
                new ArchiveContent.FileEntry("conf/settings.xml", unknownHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size());
        assertEquals(1, content.unmatchedFiles().size());
        assertEquals("conf/settings.xml", content.unmatchedFiles().get(0).path());
    }

    @Test
    void emptyEntriesProducesEmptyContent() {
        when(project.getArtifacts()).thenReturn(Set.of());

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(List.of(), null);

        assertEquals(0, content.mavenEntries().size());
        assertEquals(0, content.unmatchedFiles().size());
        assertEquals(0, content.nestedEntries().size());
    }

    @Test
    void duplicateHashFailsWhenConfigured() throws Exception {
        Path fileA = createTestFile("a.jar", "same-content");
        Path fileB = createTestFile("b.jar", "same-content");
        Artifact a = createArtifact("org.example", "a", "1.0", "jar", fileA.toFile());
        Artifact b = createArtifact("org.example", "b", "2.0", "jar", fileB.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(a, b));

        String hash = SbomUtils.computeHash(digest, fileA);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("lib/a.jar", hash));

        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest, true);
        assertThrows(IllegalStateException.class,
                () -> analyzer.analyze(entries, null));
    }

    @Test
    void shadedJarIdentifiedByFilenameMatchWithBundledDeps() throws Exception {
        // Create a shaded JAR with multiple pom.properties — filename matches "shaded"
        Path shadedJar = createShadedJarWithMultiplePomProperties("shaded-1.0.jar",
                "com.example", "shaded", "1.0",
                "com.bundled", "bundled-lib", "2.0",
                "shaded-content");

        // Create a normal nested JAR (identification will succeed via single pom.properties)
        Path normalJar = createJarWithPomProperties("normal-1.0.jar",
                "org.normal", "normal", "1.0", "normal-content");

        // Create a WAR containing both JARs
        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/shaded-1.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("WEB-INF/lib/normal-1.0.jar"));
            jos.write(Files.readAllBytes(normalJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "app", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String shadedHash = SbomUtils.computeHash(digest, shadedJar);
        String normalHash = SbomUtils.computeHash(digest, normalJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/app/WEB-INF/lib/shaded-1.0.jar", shadedHash),
                new ArchiveContent.FileEntry("web/app/WEB-INF/lib/normal-1.0.jar", normalHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "WAR should be matched");
        assertEquals("app", content.mavenEntries().get(0).artifactId().artifactId());
        // shaded JAR (owner) + normal JAR + bundled-lib (bundled dep)
        assertEquals(3, content.nestedEntries().size());
        assertTrue(content.nestedEntries().stream()
                .anyMatch(e -> "shaded".equals(e.artifactId().artifactId())
                        && "com.example".equals(e.artifactId().groupId())),
                "shaded JAR should be identified as nested artifact");
        assertTrue(content.nestedEntries().stream()
                .anyMatch(e -> "normal".equals(e.artifactId().artifactId())),
                "normal JAR should be identified as nested artifact");
        // bundled dep should be nested under the shaded JAR, not under the WAR
        var bundledEntry = content.nestedEntries().stream()
                .filter(e -> "bundled-lib".equals(e.artifactId().artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry, "bundled dep should be recorded");
        assertEquals("shaded", bundledEntry.parentId().artifactId(),
                "bundled dep parent should be the shaded JAR");
        assertTrue(content.explicitDependencies().stream()
                .noneMatch(e -> "bundled-lib".equals(e.child().artifactId())),
                "bundled dep should not have a dependency edge (nesting is sufficient)");
        assertEquals(0, content.unmatchedFiles().size());
    }

    @Test
    void hashIdentifiedShadedJarStillDetectsBundledDeps() throws Exception {
        // Shaded JAR with owner + bundled dep inside
        Path shadedJar = createShadedJarWithMultiplePomProperties("nimbus-1.0.jar",
                "com.nimbusds", "nimbus", "1.0",
                "com.bundled", "jcip-annotations", "2.0",
                "nimbus-content");

        Artifact shadedArtifact = createArtifact("com.nimbusds", "nimbus", "1.0", "jar",
                shadedJar.toFile());

        // WAR containing the shaded JAR
        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/nimbus-1.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "app", "1.0", "war",
                warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        // Reactor module makes the shaded JAR appear in nestedArtifactsByHash
        MavenProject warProject = mock(MavenProject.class);
        when(warProject.getGroupId()).thenReturn("org.example");
        when(warProject.getArtifactId()).thenReturn("app");
        when(warProject.getVersion()).thenReturn("1.0");
        when(warProject.getPackaging()).thenReturn("war");
        when(warProject.getArtifacts()).thenReturn(Set.of(shadedArtifact));
        when(session.getProjects()).thenReturn(List.of(warProject));

        String shadedHash = SbomUtils.computeHash(digest, shadedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/app/WEB-INF/lib/nimbus-1.0.jar", shadedHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "WAR should be matched");
        assertTrue(content.nestedEntries().stream()
                .anyMatch(e -> "nimbus".equals(e.artifactId().artifactId())),
                "shaded JAR should be identified as nested artifact");
        // Bundled dep must be detected even though the owner was hash-identified
        var bundledEntry = content.nestedEntries().stream()
                .filter(e -> "jcip-annotations".equals(e.artifactId().artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry,
                "bundled dep should be recorded even when owner is hash-identified");
        assertEquals("nimbus", bundledEntry.parentId().artifactId(),
                "bundled dep parent should be the shaded JAR");
    }

    @Test
    void shadedJarWithSubstringArtifactIdResolvesToLongestMatch() throws Exception {
        // log4j-api bundles log4j — both match the filename, but log4j-api
        // is the longer (more specific) match and should be chosen as owner
        Path shadedJar = createShadedJarWithMultiplePomProperties("log4j-api-2.0.jar",
                "org.apache.logging", "log4j-api", "2.0",
                "org.apache.logging", "log4j", "2.0",
                "log4j-api-content");

        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/log4j-api-2.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "app", "1.0", "war",
                warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/app/WEB-INF/lib/log4j-api-2.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "WAR should be matched");
        assertTrue(content.nestedEntries().stream()
                .anyMatch(e -> "log4j-api".equals(e.artifactId().artifactId())),
                "log4j-api should be identified as the owner");
        var bundledEntry = content.nestedEntries().stream()
                .filter(e -> "log4j".equals(e.artifactId().artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry, "log4j should be recorded as bundled dep");
        assertEquals("log4j-api", bundledEntry.parentId().artifactId(),
                "log4j should be nested under log4j-api");
        assertEquals(0, content.unmatchedFiles().size());
    }

    @Test
    void shadedJarWithAmbiguousFilenameNestedUnderFile() throws Exception {
        // Both artifactIds match the filename — can't determine owner,
        // so all artifacts are nested under the file component
        Path shadedJar = createShadedJarWithMultiplePomProperties("ab-cd-1.0.jar",
                "com.example", "ab", "1.0",
                "com.other", "cd", "2.0",
                "ambiguous-content");

        Path warFile = tempDir.resolve("myapp-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/ab-cd-1.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "myapp", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/myapp/WEB-INF/lib/ab-cd-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "WAR should be matched");
        assertEquals(0, content.nestedEntries().size(),
                "ambiguous match should not produce nested Maven entries");
        assertEquals(1, content.unmatchedFiles().size(),
                "JAR should be preserved as unmatched file");
        assertEquals(2, content.fileNestedArtifacts().size(),
                "both artifacts should be nested under the file");
        assertTrue(content.fileNestedArtifacts().stream()
                .allMatch(e -> "web/myapp/WEB-INF/lib/ab-cd-1.0.jar".equals(e.filePath())),
                "all file-nested artifacts should reference the JAR path");
        assertTrue(content.fileNestedArtifacts().stream()
                .anyMatch(e -> "ab".equals(e.artifactId().artifactId())));
        assertTrue(content.fileNestedArtifacts().stream()
                .anyMatch(e -> "cd".equals(e.artifactId().artifactId())));
    }

    @Test
    void shadedJarWithNoFilenameMatchNestedUnderFile() throws Exception {
        // Neither artifactId appears in the filename — all nested under file
        Path shadedJar = createShadedJarWithMultiplePomProperties("mystery-1.0.jar",
                "com.example", "alpha", "1.0",
                "com.other", "beta", "2.0",
                "mystery-content");

        Path warFile = tempDir.resolve("webapp-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/mystery-1.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "webapp", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/webapp/WEB-INF/lib/mystery-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "WAR should be matched");
        assertEquals(0, content.nestedEntries().size());
        assertEquals(1, content.unmatchedFiles().size(),
                "JAR should be preserved as unmatched file");
        assertEquals(2, content.fileNestedArtifacts().size(),
                "both artifacts should be nested under the file");
        assertTrue(content.fileNestedArtifacts().stream()
                .anyMatch(e -> "alpha".equals(e.artifactId().artifactId())));
        assertTrue(content.fileNestedArtifacts().stream()
                .anyMatch(e -> "beta".equals(e.artifactId().artifactId())));
    }

    @Test
    void shadedJarWithMissingOwnerVersionFallsBackToFileNested() throws Exception {
        // Owner pom.properties has no version — tryRegisterFromProps will fail.
        // Bundled dep info must not be silently lost.
        Path shadedJar = tempDir.resolve("shaded-1.0.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(shadedJar))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write("content".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/maven/com.example/shaded/pom.properties"));
            jos.write("groupId=com.example\nartifactId=shaded\n".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/maven/com.bundled/lib/pom.properties"));
            jos.write("groupId=com.bundled\nartifactId=lib\nversion=2.0\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }

        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/shaded-1.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "app", "1.0", "war",
                warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<ArchiveContent.FileEntry> entries = List.of(
                new ArchiveContent.FileEntry("web/app/WEB-INF/lib/shaded-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        ArchiveContent content = analyzer.analyze(entries, null);

        assertEquals(1, content.mavenEntries().size(), "WAR should be matched");
        // Owner registration failed, so the JAR should be unmatched
        assertEquals(1, content.unmatchedFiles().size(),
                "shaded JAR should be preserved as unmatched file");
        // The bundled dep with valid coords must still be recorded
        assertTrue(content.fileNestedArtifacts().stream()
                .anyMatch(e -> "lib".equals(e.artifactId().artifactId())),
                "bundled dep should be recorded as file-nested artifact");
    }

    // --- helpers ---

    private ArchiveAnalyzer createAnalyzer() {
        return new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest, false);
    }

    private Path createTestJar(String name, String content) throws Exception {
        Path jarPath = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jarPath;
    }

    private Path createJarWithPomProperties(String name, String groupId,
            String artifactId, String version, String content) throws Exception {
        Path jarPath = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            String propsPath = "META-INF/maven/" + groupId + "/" + artifactId
                    + "/pom.properties";
            jos.putNextEntry(new JarEntry(propsPath));
            String props = "groupId=" + groupId + "\n"
                    + "artifactId=" + artifactId + "\n"
                    + "version=" + version + "\n";
            jos.write(props.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jarPath;
    }

    private Path createShadedJarWithMultiplePomProperties(String name,
            String groupId1, String artifactId1, String version1,
            String groupId2, String artifactId2, String version2,
            String content) throws Exception {
        Path jarPath = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            String props1Path = "META-INF/maven/" + groupId1 + "/" + artifactId1
                    + "/pom.properties";
            jos.putNextEntry(new JarEntry(props1Path));
            jos.write(("groupId=" + groupId1 + "\nartifactId=" + artifactId1
                    + "\nversion=" + version1 + "\n").getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            String props2Path = "META-INF/maven/" + groupId2 + "/" + artifactId2
                    + "/pom.properties";
            jos.putNextEntry(new JarEntry(props2Path));
            jos.write(("groupId=" + groupId2 + "\nartifactId=" + artifactId2
                    + "\nversion=" + version2 + "\n").getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jarPath;
    }

    private Path createTestFile(String name, String content) throws Exception {
        Path path = tempDir.resolve(name);
        Files.writeString(path, content);
        return path;
    }

    private static Artifact createArtifact(String groupId, String artifactId,
            String version, String type, File file) {
        DefaultArtifact artifact = new DefaultArtifact(
                groupId, artifactId, version, "compile", type, null,
                new DefaultArtifactHandler(type));
        artifact.setFile(file);
        return artifact;
    }
}
