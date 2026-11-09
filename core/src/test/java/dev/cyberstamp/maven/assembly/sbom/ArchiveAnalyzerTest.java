package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.eclipse.aether.RepositorySystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.sun.net.httpserver.HttpServer;

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
        Build build = new Build();
        build.setDirectory(tempDir.resolve("target").toString());
        lenient().when(project.getBuild()).thenReturn(build);
    }

    @Test
    void matchedArtifactClassifiedAsMavenEntry() throws Exception {
        Path jarFile = createTestJar("lib-a-1.0.jar", "content-a");
        Artifact artifact = createArtifact("org.example", "lib-a", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, jarFile);
        List<FileEntry> entries = List.of(
                new FileEntry("lib/lib-a-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        List<PackageComponent> packages = extractPackageComponents(model);
        List<FileComponent> files = extractFileComponents(model);
        assertEquals(1, packages.size());
        assertEquals(0, files.size());
        assertEquals("org.example", ((ArtifactCoords) packages.get(0).ref()).groupId());
        assertEquals("lib/lib-a-1.0.jar", packages.get(0).archivePath());
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
        List<FileEntry> entries = List.of(
                new FileEntry("lib/nimbus-jose-jwt-10.9.1.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        List<PackageComponent> topLevel = extractPackageComponents(model);
        assertEquals(1, topLevel.size());
        assertEquals("nimbus-jose-jwt", ((ArtifactCoords) topLevel.get(0).ref()).artifactId());

        // Find the bundled dep in nested components
        var bundledEntry = extractNestedPackages(model).stream()
                .filter(e -> "jcip-annotations".equals(((ArtifactCoords) e.ref()).artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry,
                "bundled dep should be detected in top-level shaded JAR");
        // Parent relationship is implicit via nesting, so just verify it's nested
        assertTrue(topLevel.get(0).nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && "jcip-annotations".equals(((ArtifactCoords) pkg.ref()).artifactId())),
                "bundled dep should be nested under the shaded JAR");
    }

    @Test
    void unmatchedFileClassifiedCorrectly() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest,
                new ByteArrayInputStream("config-data".getBytes(StandardCharsets.UTF_8)));
        List<FileEntry> entries = List.of(
                new FileEntry("conf/app.properties", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(0, extractPackageComponents(model).size());
        assertEquals(1, extractFileComponents(model).size());
        assertEquals("conf/app.properties", extractFileComponents(model).get(0).archivePath());
    }

    @Test
    void baseDirPrefixStripped() throws Exception {
        Path jarFile = createTestJar("lib-a-1.0.jar", "content-strip");
        Artifact artifact = createArtifact("org.example", "lib-a", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, jarFile);
        List<FileEntry> entries = List.of(new FileEntry("myapp-1.0/lib/lib-a-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, "myapp-1.0/");

        assertEquals(1, extractPackageComponents(model).size());
        assertEquals("lib/lib-a-1.0.jar", extractPackageComponents(model).get(0).archivePath());
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
        List<FileEntry> entries = List.of(new FileEntry("web/entry.txt", entryHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size());
        assertEquals("mywar", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).artifactId());
        assertEquals(1, extractFileComponents(model).size(),
                "non-identifiable nested file should be preserved as unmatched");
    }

    @Test
    void sourceFileOutsideBuildDirExcludedFromUnpackDetection() throws Exception {
        Path sourceDir = tempDir.resolve("src");
        Files.createDirectories(sourceDir);
        Path licenseFile = Files.writeString(sourceDir.resolve("LICENSE.txt"),
                "Apache License 2.0 text");

        Path depJar = tempDir.resolve("dep-1.0.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(depJar))) {
            jos.putNextEntry(new JarEntry("META-INF/LICENSE"));
            jos.write(Files.readAllBytes(licenseFile));
            jos.closeEntry();
        }

        Artifact depArtifact = createArtifact("org.example", "dep", "1.0", "jar",
                depJar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(depArtifact));

        String licenseHash = SbomUtils.computeHash(digest, licenseFile);
        List<FileEntry> entries = List.of(new FileEntry("LICENSE.txt", licenseHash, licenseFile.toFile()));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertTrue(extractPackageComponents(model).isEmpty(),
                "dependency should not be detected as unpacked from a project source file hash match");
        assertEquals(1, extractFileComponents(model).size(),
                "source file should remain as unmatched");
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
        List<FileEntry> entries = List.of(
                new FileEntry("web/parent/WEB-INF/lib/nested-1.0.jar", nestedHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "parent WAR should be matched");
        assertEquals(1, extractNestedPackages(model).size(), "nested JAR should be identified");
        assertEquals("nested", ((ArtifactCoords) extractNestedPackages(model).get(0).ref()).artifactId());
        assertEquals("org.nested", ((ArtifactCoords) extractNestedPackages(model).get(0).ref()).groupId());
    }

    @Test
    void multipleEntriesMixedClassification() throws Exception {
        Path jarFile = createTestJar("known-1.0.jar", "known-content");
        Artifact artifact = createArtifact("org.example", "known", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String knownHash = SbomUtils.computeHash(digest, jarFile);
        String unknownHash = SbomUtils.computeHash(digest,
                new ByteArrayInputStream("unknown-content".getBytes(StandardCharsets.UTF_8)));

        List<FileEntry> entries = List.of(
                new FileEntry("lib/known-1.0.jar", knownHash),
                new FileEntry("conf/settings.xml", unknownHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size());
        assertEquals(1, extractFileComponents(model).size());
        assertEquals("conf/settings.xml", extractFileComponents(model).get(0).archivePath());
    }

    @Test
    void emptyEntriesProducesEmptyContent() {
        when(project.getArtifacts()).thenReturn(Set.of());

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(List.of(), null);

        assertEquals(0, extractPackageComponents(model).size());
        assertEquals(0, extractFileComponents(model).size());
        assertEquals(0, extractNestedPackages(model).size());
    }

    @Test
    void duplicateHashFailsWhenConfigured() throws Exception {
        Path fileA = createTestFile("a.jar", "same-content");
        Path fileB = createTestFile("b.jar", "same-content");
        Artifact a = createArtifact("org.example", "a", "1.0", "jar", fileA.toFile());
        Artifact b = createArtifact("org.example", "b", "2.0", "jar", fileB.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(a, b));

        String hash = SbomUtils.computeHash(digest, fileA);
        List<FileEntry> entries = List.of(new FileEntry("lib/a.jar", hash));

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
        List<FileEntry> entries = List.of(
                new FileEntry("web/app/WEB-INF/lib/shaded-1.0.jar", shadedHash),
                new FileEntry("web/app/WEB-INF/lib/normal-1.0.jar", normalHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "WAR should be matched");
        assertEquals("app", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).artifactId());
        // shaded JAR (owner) + normal JAR + bundled-lib (bundled dep)
        assertEquals(3, extractNestedPackages(model).size());
        assertTrue(extractNestedPackages(model).stream()
                .anyMatch(e -> "shaded".equals(((ArtifactCoords) e.ref()).artifactId())
                        && "com.example".equals(((ArtifactCoords) e.ref()).groupId())),
                "shaded JAR should be identified as nested artifact");
        assertTrue(extractNestedPackages(model).stream()
                .anyMatch(e -> "normal".equals(((ArtifactCoords) e.ref()).artifactId())),
                "normal JAR should be identified as nested artifact");
        // bundled dep should be nested under the shaded JAR, not under the WAR
        var bundledEntry = extractNestedPackages(model).stream()
                .filter(e -> "bundled-lib".equals(((ArtifactCoords) e.ref()).artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry, "bundled dep should be recorded");
        assertTrue(isNestedUnder(model, "bundled-lib", "shaded"),
                "bundled dep parent should be the shaded JAR");
        assertTrue(model.dependencyEdges().stream()
                .noneMatch(e -> e.child() instanceof ArtifactCoords coords
                        && "bundled-lib".equals(coords.artifactId())),
                "bundled dep should not have a dependency edge (nesting is sufficient)");
        assertEquals(0, extractFileComponents(model).size());
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
        List<FileEntry> entries = List.of(
                new FileEntry("web/app/WEB-INF/lib/nimbus-1.0.jar", shadedHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "WAR should be matched");
        assertTrue(extractNestedPackages(model).stream()
                .anyMatch(e -> "nimbus".equals(((ArtifactCoords) e.ref()).artifactId())),
                "shaded JAR should be identified as nested artifact");
        // Bundled dep must be detected even though the owner was hash-identified
        var bundledEntry = extractNestedPackages(model).stream()
                .filter(e -> "jcip-annotations".equals(((ArtifactCoords) e.ref()).artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry,
                "bundled dep should be recorded even when owner is hash-identified");
        assertTrue(isNestedUnder(model, "jcip-annotations", "nimbus"),
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
        List<FileEntry> entries = List.of(
                new FileEntry("web/app/WEB-INF/lib/log4j-api-2.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "WAR should be matched");
        assertTrue(extractNestedPackages(model).stream()
                .anyMatch(e -> "log4j-api".equals(((ArtifactCoords) e.ref()).artifactId())),
                "log4j-api should be identified as the owner");
        var bundledEntry = extractNestedPackages(model).stream()
                .filter(e -> "log4j".equals(((ArtifactCoords) e.ref()).artifactId()))
                .findFirst().orElse(null);
        assertNotNull(bundledEntry, "log4j should be recorded as bundled dep");
        assertTrue(isNestedUnder(model, "log4j", "log4j-api"),
                "log4j should be nested under log4j-api");
        assertEquals(0, extractFileComponents(model).size());
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
        List<FileEntry> entries = List.of(
                new FileEntry("web/myapp/WEB-INF/lib/ab-cd-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "WAR should be matched");
        assertEquals(0, extractNestedPackages(model).size(),
                "ambiguous match should not produce nested Maven entries");
        assertEquals(1, extractFileComponents(model).size(),
                "JAR should be preserved as unmatched file");
        assertEquals(2, countFileNestedPackages(model),
                "both artifacts should be nested under the file");
        // Check that the file component for the JAR has nested packages
        FileComponent jarFile = extractFileComponents(model).stream()
                .filter(f -> "web/myapp/WEB-INF/lib/ab-cd-1.0.jar".equals(f.archivePath()))
                .findFirst().orElse(null);
        assertNotNull(jarFile, "JAR file component should exist");
        assertEquals(2, jarFile.nested().size(), "file should have 2 nested packages");
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("ab")));
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("cd")));
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
        List<FileEntry> entries = List.of(
                new FileEntry("web/webapp/WEB-INF/lib/mystery-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "WAR should be matched");
        assertEquals(0, extractNestedPackages(model).size());
        assertEquals(1, extractFileComponents(model).size(),
                "JAR should be preserved as unmatched file");
        assertEquals(2, countFileNestedPackages(model),
                "both artifacts should be nested under the file");
        // Check file-nested packages
        FileComponent jarFile = extractFileComponents(model).get(0);
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("alpha")));
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("beta")));
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
        List<FileEntry> entries = List.of(
                new FileEntry("web/app/WEB-INF/lib/shaded-1.0.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(), "WAR should be matched");
        // Owner registration failed, so the JAR should be unmatched
        assertEquals(1, extractFileComponents(model).size(),
                "shaded JAR should be preserved as unmatched file");
        // The bundled dep with valid coords must still be recorded
        FileComponent jarFile = extractFileComponents(model).get(0);
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("lib")),
                "bundled dep should be recorded as file-nested artifact");
    }

    @Test
    void nonDependencyJarWithPomPropertiesDetectedAsMaven() throws Exception {
        Path jarFile = createJarWithPomProperties("external-lib-3.0.jar",
                "com.external", "external-lib", "3.0", "external-content");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, jarFile);
        List<FileEntry> entries = List.of(
                new FileEntry("lib/external-lib-3.0.jar", hash, jarFile.toFile()));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(),
                "non-dependency JAR with pom.properties should be detected as Maven");
        assertEquals("com.external", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).groupId());
        assertEquals("external-lib", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).artifactId());
        assertEquals("3.0", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).version());
        assertEquals("lib/external-lib-3.0.jar", extractPackageComponents(model).get(0).archivePath());
        assertEquals(0, extractFileComponents(model).size(),
                "identified JAR should not remain as unmatched file");
    }

    @Test
    void nonDependencyShadedJarOwnerIdentifiedWithBundledDeps() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("nimbus-jose-jwt-10.0.jar",
                "com.nimbusds", "nimbus-jose-jwt", "10.0",
                "com.google.code.gson", "gson", "2.11.0",
                "nimbus-content");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<FileEntry> entries = List.of(
                new FileEntry("lib/nimbus-jose-jwt-10.0.jar", hash,
                        shadedJar.toFile()));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(1, extractPackageComponents(model).size(),
                "shaded JAR owner should be detected as Maven entry");
        assertEquals("nimbus-jose-jwt", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).artifactId());
        assertEquals("com.nimbusds", ((ArtifactCoords) extractPackageComponents(model).get(0).ref()).groupId());

        assertEquals(1, extractNestedPackages(model).size(),
                "bundled dep should be recorded as nested entry");
        assertEquals("gson", ((ArtifactCoords) extractNestedPackages(model).get(0).ref()).artifactId());
        assertTrue(isNestedUnder(model, "gson", "nimbus-jose-jwt"),
                "gson should be nested under nimbus-jose-jwt");

        assertEquals(0, extractFileComponents(model).size());
        // File-nested artifacts are now PackageComponents nested under FileComponents
        assertEquals(0, countFileNestedPackages(model));
    }

    @Test
    void nonDependencyShadedJarAmbiguousOwnerFallsBackToFileNested() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("ab-cd-1.0.jar",
                "com.example", "ab", "1.0",
                "com.other", "cd", "2.0",
                "ambiguous-content");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<FileEntry> entries = List.of(
                new FileEntry("lib/ab-cd-1.0.jar", hash,
                        shadedJar.toFile()));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        assertEquals(0, extractPackageComponents(model).size(),
                "ambiguous shaded JAR should not produce a Maven entry");
        assertEquals(0, extractNestedPackages(model).size());
        assertEquals(1, extractFileComponents(model).size(),
                "JAR should remain as unmatched file");
        assertEquals(2, countFileNestedPackages(model),
                "both artifacts should be recorded as file-nested");
        FileComponent jarFile = extractFileComponents(model).get(0);
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("ab")));
        assertTrue(jarFile.nested().stream()
                .anyMatch(n -> n instanceof PackageComponent pkg
                        && ((ArtifactCoords) pkg.ref()).artifactId().equals("cd")));
        // All file-nested packages should be under the same JAR file
        assertEquals("lib/ab-cd-1.0.jar", jarFile.archivePath());
    }

    @Test
    void reclassificationSkipsRootLevelUnpackedArtifact() throws Exception {
        Path entryFile = createTestFile("root-entry.txt", "root-entry-data");
        byte[] entryBytes = Files.readAllBytes(entryFile);

        // Create a WAR that contains the entry
        Path warFile = tempDir.resolve("root-war-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("root-entry.txt"));
            jos.write(entryBytes);
            jos.closeEntry();
        }
        Artifact warArtifact = createArtifact("org.example", "root-war", "1.0", "war",
                warFile.toFile());

        // Create an independent JAR
        Path jarFile = createTestJar("independent-1.0.jar", "independent-content");
        Artifact jarArtifact = createArtifact("org.example", "independent", "1.0", "jar",
                jarFile.toFile());

        when(project.getArtifacts()).thenReturn(Set.of(warArtifact, jarArtifact));

        String entryHash = SbomUtils.computeHash(digest, entryFile);
        String jarHash = SbomUtils.computeHash(digest, jarFile);
        // WAR is unpacked at root (empty archivePath prefix),
        // independent JAR is alongside it
        List<FileEntry> entries = List.of(
                new FileEntry("root-entry.txt", entryHash),
                new FileEntry("lib/independent-1.0.jar", jarHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        // Independent JAR should remain top-level, NOT reclassified under the WAR
        assertTrue(extractPackageComponents(model).stream()
                .anyMatch(e -> "independent".equals(((ArtifactCoords) e.ref()).artifactId())),
                "independent JAR should remain as top-level maven entry");
        assertFalse(extractNestedPackages(model).stream()
                .anyMatch(e -> "independent".equals(((ArtifactCoords) e.ref()).artifactId())),
                "independent JAR should NOT be reclassified as nested");
    }

    @Test
    void reclassificationPicksLongestMatchingPrefix() throws Exception {
        Path innerJar = createTestJar("inner-1.0.jar", "inner-content");
        byte[] innerBytes = Files.readAllBytes(innerJar);

        // Create outer WAR containing inner JAR
        Path outerWar = tempDir.resolve("outer-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(outerWar))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/inner-1.0.jar"));
            jos.write(innerBytes);
            jos.closeEntry();
        }

        // Create a distribution-level WAR that contains the outer WAR's content
        Path distWar = tempDir.resolve("dist-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(distWar))) {
            jos.putNextEntry(new JarEntry("web/outer/WEB-INF/lib/inner-1.0.jar"));
            jos.write(innerBytes);
            jos.closeEntry();
        }

        Artifact outerArtifact = createArtifact("org.example", "outer", "1.0", "war",
                outerWar.toFile());
        Artifact distArtifact = createArtifact("org.example", "dist", "1.0", "war",
                distWar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(outerArtifact, distArtifact));

        String innerHash = SbomUtils.computeHash(digest, innerJar);
        // Both WARs are unpacked: dist at "web/" and outer at "web/outer/"
        // inner JAR is at "web/outer/WEB-INF/lib/inner-1.0.jar"
        List<FileEntry> entries = List.of(
                new FileEntry("web/outer/WEB-INF/lib/inner-1.0.jar", innerHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        // inner JAR should be nested under outer (longer prefix), not dist
        if (!extractNestedPackages(model).isEmpty()) {
            assertTrue(isNestedUnder(model, "inner", "outer"),
                    "inner JAR should be nested under outer (longest matching prefix)");
            assertFalse(isNestedUnder(model, "inner", "dist"),
                    "inner JAR should NOT be nested under dist (shorter prefix)");
        }
    }

    @Test
    void reclassifiedUnpackedChildDoesNotCreateDependencyEdge() throws Exception {
        // A resource that lives inside the WAR, so the WAR is detected as
        // unpacked at prefix "web/app/".
        Path resFile = createTestFile("res.txt", "war-marker-content");
        byte[] resBytes = Files.readAllBytes(resFile);
        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("res.txt"));
            jos.write(resBytes);
            jos.closeEntry();
        }
        Artifact warArtifact = createArtifact("org.example", "app", "1.0", "war",
                warFile.toFile());

        // An independent JAR artifact that is hash-matched as a top-level
        // component but physically sits under the WAR's unpack directory.
        // It is NOT contained in the WAR, so it is reachable only via the
        // reclassification pass (not via nested-artifact identification).
        Path extraJar = createTestJar("extra-1.0.jar", "extra-content");
        Artifact extraArtifact = createArtifact("org.example", "extra", "1.0", "jar",
                extraJar.toFile());

        when(project.getArtifacts()).thenReturn(Set.of(warArtifact, extraArtifact));

        String resHash = SbomUtils.computeHash(digest, resFile);
        String extraHash = SbomUtils.computeHash(digest, extraJar);
        List<FileEntry> entries = List.of(
                new FileEntry("web/app/res.txt", resHash),
                new FileEntry("web/app/extra-1.0.jar", extraHash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        // The extra JAR is reclassified as nested under the unpacked WAR ...
        assertTrue(isNestedUnder(model, "extra", "app"),
                "extra JAR should be reclassified as nested under the unpacked WAR");
        // ... but reclassification expresses containment via nesting only and
        // must NOT emit a dependency edge (matches pre-refactor behavior and
        // the DependencyEdge contract that containment is not a dependency).
        assertTrue(model.dependencyEdges().stream()
                .noneMatch(e -> e.child() instanceof ArtifactCoords coords
                        && "extra".equals(coords.artifactId())),
                "reclassified unpacked child must not have a dependency edge");
    }

    @Test
    void matchAgainstExternalSbomsReplacesStaleOccurrences() throws Exception {
        // An archive entry that doesn't match any Maven artifact
        Path jarFile = createTestJar("h2-2.4.jar", "h2-content");
        String hash = SbomUtils.computeHash(digest, jarFile);
        when(project.getArtifacts()).thenReturn(Set.of());

        // External SBOM has this component with a stale occurrence path
        Bom externalBom = new Bom();
        Component extComp = new Component();
        extComp.setType(Component.Type.LIBRARY);
        extComp.setName("h2");
        extComp.setPurl("pkg:maven/com.h2database/h2@2.4");
        extComp.setBomRef("pkg:maven/com.h2database/h2@2.4");
        extComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        Evidence evidence = new Evidence();
        Occurrence staleOcc = new Occurrence();
        staleOcc.setLocation("lib/main/com.h2database.h2-2.4.jar");
        evidence.addOccurrence(staleOcc);
        extComp.setEvidence(evidence);
        externalBom.setComponents(new ArrayList<>(List.of(extComp)));

        List<FileEntry> entries = List.of(
                new FileEntry("lib/lib/main/com.h2database.h2-2.4.jar", hash));

        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(externalBom), false);
        analyzer.analyze(entries, null);

        // The stale occurrence should be replaced with the archive path
        List<Occurrence> occs = extComp.getEvidence().getOccurrences();
        assertEquals(1, occs.size(),
                "should have exactly one occurrence (stale replaced, not appended)");
        assertEquals("lib/lib/main/com.h2database.h2-2.4.jar",
                occs.get(0).getLocation(),
                "occurrence should be the actual archive path");
    }

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

    // Helper methods to extract components from AssemblyComponents model

    private List<PackageComponent> extractPackageComponents(AssemblyComponents model) {
        List<PackageComponent> result = new ArrayList<>();
        for (AssemblyComponent comp : model.components()) {
            if (comp instanceof PackageComponent pkg) {
                result.add(pkg);
            }
        }
        return result;
    }

    private List<FileComponent> extractFileComponents(AssemblyComponents model) {
        List<FileComponent> result = new ArrayList<>();
        for (AssemblyComponent comp : model.components()) {
            if (comp instanceof FileComponent file) {
                result.add(file);
            }
        }
        return result;
    }

    private List<PackageComponent> extractNestedPackages(AssemblyComponents model) {
        List<PackageComponent> result = new ArrayList<>();
        for (AssemblyComponent comp : model.components()) {
            collectNestedPackages(comp, result);
        }
        return result;
    }

    private void collectNestedPackages(AssemblyComponent comp,
            List<PackageComponent> result) {
        if (comp instanceof PackageComponent pkg) {
            for (AssemblyComponent nested : pkg.nested()) {
                if (nested instanceof PackageComponent nestedPkg) {
                    result.add(nestedPkg);
                }
                collectNestedPackages(nested, result);
            }
        }
        // FileComponent nested packages are file-nested artifacts, not nested Maven entries
        // so we don't collect them here
    }

    /**
     * Checks if a package component with the given artifactId is nested under
     * a parent with the given parent artifactId.
     */
    private boolean isNestedUnder(AssemblyComponents model, String childArtifactId, String parentArtifactId) {
        for (AssemblyComponent comp : model.components()) {
            if (comp instanceof PackageComponent pkg) {
                if (pkg.ref() instanceof ArtifactCoords coords
                        && parentArtifactId.equals(coords.artifactId())) {
                    // Check if this parent contains the child in its nested list
                    return containsNestedWithArtifactId(pkg, childArtifactId);
                }
                // Recursively check nested components
                if (checkNestedForParentChild(pkg, childArtifactId, parentArtifactId)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean checkNestedForParentChild(PackageComponent parent, String childArtifactId, String parentArtifactId) {
        for (AssemblyComponent nested : parent.nested()) {
            if (nested instanceof PackageComponent nestedPkg) {
                if (nestedPkg.ref() instanceof ArtifactCoords coords
                        && parentArtifactId.equals(coords.artifactId())) {
                    if (containsNestedWithArtifactId(nestedPkg, childArtifactId)) {
                        return true;
                    }
                }
                if (checkNestedForParentChild(nestedPkg, childArtifactId, parentArtifactId)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean containsNestedWithArtifactId(PackageComponent parent, String childArtifactId) {
        for (AssemblyComponent nested : parent.nested()) {
            if (nested instanceof PackageComponent nestedPkg) {
                if (nestedPkg.ref() instanceof ArtifactCoords coords
                        && childArtifactId.equals(coords.artifactId())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Counts PackageComponents nested under FileComponents (file-nested artifacts).
     */
    private int countFileNestedPackages(AssemblyComponents model) {
        int count = 0;
        for (AssemblyComponent comp : model.components()) {
            if (comp instanceof FileComponent file) {
                for (AssemblyComponent nested : file.nested()) {
                    if (nested instanceof PackageComponent) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    // ---- Identification ----

    @Test
    void hashMatchedEntryRecordsHashComparison() throws Exception {
        Path jarFile = createTestJar("lib-x-1.0.jar", "content-x");
        Artifact artifact = createArtifact("org.example", "lib-x", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, jarFile);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("lib/lib-x-1.0.jar", hash)), null);

        List<PackageComponent> packages = extractPackageComponents(model);
        assertEquals(1, packages.size());
        assertEquals(Identification.hashMatch(), packages.get(0).identification());
    }

    @Test
    void pomPropertiesIdentifiedJarRecordsManifestAnalysis() throws Exception {
        Path jarFile = createJarWithPomProperties("lib-y-2.0.jar",
                "org.example", "lib-y", "2.0", "content-y");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, jarFile);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("lib/lib-y-2.0.jar", hash, jarFile.toFile())), null);

        List<PackageComponent> packages = extractPackageComponents(model);
        assertEquals(1, packages.size());
        assertEquals(Identification.pomProperties(), packages.get(0).identification());
    }

    @Test
    void filenameResolvedShadedOwnerRecordsReducedConfidence() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("lib-z-3.0.jar",
                "org.example", "lib-z", "3.0",
                "com.bundled", "shaded-a", "1.5",
                "shaded-content");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, shadedJar);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("lib/lib-z-3.0.jar", hash, shadedJar.toFile())), null);

        List<PackageComponent> packages = extractPackageComponents(model);
        assertEquals(1, packages.size());
        assertEquals(Identification.pomPropertiesFilenameOwner(), packages.get(0).identification());
    }

    /**
     * The filename heuristic decides which descriptor is the jar itself, i.e.
     * the owner's identity; a bundled dep's coordinates are read verbatim from
     * its own descriptor whichever owner was chosen.
     */
    @Test
    void bundledDepOfFilenameResolvedOwnerHasFullConfidence() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("lib-w-4.0.jar",
                "org.example", "lib-w", "4.0",
                "com.bundled", "shaded-b", "2.1",
                "shaded-content-w");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, shadedJar);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("lib/lib-w-4.0.jar", hash, shadedJar.toFile())), null);

        assertEquals(Identification.pomPropertiesFilenameOwner(),
                extractPackageComponents(model).get(0).identification());
        List<PackageComponent> nested = extractNestedPackages(model);
        assertEquals(1, nested.size());
        assertEquals("shaded-b", ((ArtifactCoords) nested.get(0).ref()).artifactId());
        assertEquals(Identification.pomProperties(), nested.get(0).identification());
    }

    @Test
    void bundledDepOfHashMatchedOwnerKeepsFullConfidence() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("lib-v-5.0.jar",
                "org.example", "lib-v", "5.0",
                "com.bundled", "shaded-c", "3.2",
                "shaded-content-v");
        Artifact artifact = createArtifact("org.example", "lib-v", "5.0", "jar", shadedJar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("lib/lib-v-5.0.jar", hash)), null);

        List<PackageComponent> nested = extractNestedPackages(model);
        assertEquals(1, nested.size());
        assertEquals("shaded-c", ((ArtifactCoords) nested.get(0).ref()).artifactId());
        assertEquals(Identification.pomProperties(), nested.get(0).identification());
    }

    @Test
    void unpackedArtifactReducesConfidence() throws Exception {
        Path entryFile = createTestFile("unpacked-entry.txt", "unpacked-entry-data");
        byte[] entryBytes = Files.readAllBytes(entryFile);
        Path warFile = tempDir.resolve("mywar-unpacked-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/unpacked-entry.txt"));
            jos.write(entryBytes);
            jos.closeEntry();
        }
        Artifact warArtifact = createArtifact("org.example", "mywar-unpacked", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        String entryHash = SbomUtils.computeHash(digest, entryFile);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("web/unpacked-entry.txt", entryHash)), null);

        List<PackageComponent> packages = extractPackageComponents(model);
        assertEquals(1, packages.size());
        assertEquals("mywar-unpacked", ((ArtifactCoords) packages.get(0).ref()).artifactId());
        assertEquals(Identification.unpackedContentMatch(), packages.get(0).identification());
    }

    /**
     * The filename heuristic could not choose an owner, so the descriptors are
     * nested under the file; each one's coordinates are still read verbatim
     * from its own pom.properties.
     */
    @Test
    void unresolvedShadedJarContentsGetManifestAnalysis() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("ambiguous-ab-1.0.jar",
                "com.example", "ab", "1.0",
                "com.other", "ab", "2.0", // ambiguous: both artifactIds match the filename
                "ambiguous-content");
        when(project.getArtifacts()).thenReturn(Set.of());

        String hash = SbomUtils.computeHash(digest, shadedJar);
        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("lib/ambiguous-ab-1.0.jar", hash, shadedJar.toFile())), null);

        List<FileComponent> files = extractFileComponents(model);
        assertEquals(1, files.size(), "unresolved shaded JAR should be a file component");
        assertEquals(2, countFileNestedPackages(model));
        for (AssemblyComponent nested : files.get(0).nested()) {
            assertEquals(Identification.pomProperties(), ((PackageComponent) nested).identification());
        }
    }

    @Test
    void identityEvidenceOffRecordsNoIdentification() throws Exception {
        Path jarFile = createTestJar("lib-off-1.0.jar", "content-off");
        Artifact artifact = createArtifact("org.example", "lib-off", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        ArchiveAnalyzer analyzer = createAnalyzer();
        analyzer.setIdentityEvidence(false);
        AssemblyComponents model = analyzer.analyze(
                List.of(new FileEntry("lib/lib-off-1.0.jar", SbomUtils.computeHash(digest, jarFile))), null);

        assertNull(extractPackageComponents(model).get(0).identification());
    }

    @Test
    void reclassifiedUnpackedChildKeepsItsIdentification() throws Exception {
        Path resFile = createTestFile("res.txt", "war-marker-content");
        byte[] resBytes = Files.readAllBytes(resFile);
        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("res.txt"));
            jos.write(resBytes);
            jos.closeEntry();
        }
        Artifact warArtifact = createArtifact("org.example", "app", "1.0", "war", warFile.toFile());
        Path extraJar = createTestJar("extra-1.0.jar", "extra-content");
        Artifact extraArtifact = createArtifact("org.example", "extra", "1.0", "jar", extraJar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact, extraArtifact));

        AssemblyComponents model = createAnalyzer().analyze(List.of(
                new FileEntry("web/app/res.txt", SbomUtils.computeHash(digest, resFile)),
                new FileEntry("web/app/extra-1.0.jar", SbomUtils.computeHash(digest, extraJar))), null);

        assertTrue(isNestedUnder(model, "extra", "app"));
        PackageComponent extra = extractNestedPackages(model).stream()
                .filter(p -> "extra".equals(((ArtifactCoords) p.ref()).artifactId()))
                .findFirst().orElseThrow();
        assertEquals(Identification.hashMatch(), extra.identification(),
                "reclassification must carry the hash match with the moved entry");
    }

    @Test
    void unmatchedJarIdentifiedViaRemoteChecksumLookup() throws Exception {
        Path jar = createTestJar("gradle-built-1.0.jar", "non-maven-content");
        HttpServer stub = startStubChecksumServer(
                "{\"items\":[{\"group\":\"org.gradle.example\",\"name\":\"gradle-built\",\"version\":\"1.0\"}]}");
        try {
            RemoteChecksumResolver resolver = createResolver(stub, List.of("**/*.jar"), List.of());
            ArchiveAnalyzer analyzer = createAnalyzerWithRemoteLookup(resolver);

            AssemblyComponents model = analyzer.analyze(List.of(
                    new FileEntry("lib/gradle-built-1.0.jar",
                            SbomUtils.computeHash(digest, jar), jar.toFile())),
                    null);

            List<PackageComponent> packages = extractPackageComponents(model);
            assertEquals(1, packages.size());
            ArtifactCoords coords = (ArtifactCoords) packages.get(0).ref();
            assertEquals(ArtifactCoords.of("org.gradle.example", "gradle-built", "1.0"), coords);
            assertEquals(Identification.remoteChecksumLookup(), packages.get(0).identification());
            assertEquals(0, extractFileComponents(model).size());
        } finally {
            stub.stop(0);
        }
    }

    @Test
    void unmatchedJarExcludedFromRemoteLookupStaysFileComponent() throws Exception {
        Path jar = createTestJar("excluded-1.0.jar", "non-maven-content-2");
        HttpServer stub = startStubChecksumServer(
                "{\"items\":[{\"group\":\"org.gradle.example\",\"name\":\"excluded\",\"version\":\"1.0\"}]}");
        try {
            RemoteChecksumResolver resolver = createResolver(
                    stub, List.of("**/*.jar"), List.of("**/excluded-*.jar"));
            ArchiveAnalyzer analyzer = createAnalyzerWithRemoteLookup(resolver);

            AssemblyComponents model = analyzer.analyze(List.of(
                    new FileEntry("lib/excluded-1.0.jar",
                            SbomUtils.computeHash(digest, jar), jar.toFile())),
                    null);

            assertEquals(0, extractPackageComponents(model).size());
            assertEquals(1, extractFileComponents(model).size());
        } finally {
            stub.stop(0);
        }
    }

    private HttpServer startStubChecksumServer(String responseBody) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/service/rest/v1/search", exchange -> {
            byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return server;
    }

    private RemoteChecksumResolver createResolver(HttpServer stub, List<String> includes, List<String> excludes) {
        RemoteArtifactLookup config = new RemoteArtifactLookup();
        config.setEnabled(true);
        config.setCentral(false);
        config.setIncludes(includes);
        config.setExcludes(excludes);
        config.setNexusUrl("http://127.0.0.1:" + stub.getAddress().getPort()
                + "/service/rest/v1/search?sha1=" + NexusChecksumLookup.PLACEHOLDER);
        return RemoteChecksumResolver.create(config, null, null, null, null).orElseThrow();
    }

    private ArchiveAnalyzer createAnalyzerWithRemoteLookup(RemoteChecksumResolver resolver) {
        return new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(), true, resolver);
    }
}
