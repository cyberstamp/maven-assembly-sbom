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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.eclipse.aether.RepositorySystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.sun.net.httpserver.HttpServer;

import dev.cyberstamp.maven.assembly.sbom.match.MavenArtifactMatcher;
import dev.cyberstamp.maven.assembly.sbom.match.MavenArtifactMatchers;
import dev.cyberstamp.maven.assembly.sbom.match.MavenMatch;

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
        assertTrue(topLevel.get(0).dependenciesKnown(), "a project dependency: resolved by Maven");

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
        assertFalse(bundledEntry.dependenciesKnown(),
                "known only from its pom.properties, the bundled dep's dependencies were never resolved");
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
        assertTrue(extractNestedPackages(model).get(0).dependenciesKnown(),
                "a nested jar with a file of its own is resolved as a Maven artifact");
    }

    @Test
    void nestedJarWithItsOwnFileIsNotReplacedByBundledCopyUnderAnotherParent() throws Exception {
        // x is bundled in a top-level shaded jar (pom.properties only) and
        // shipped as a file in an unpacked war: the war's x keeps its file
        Path shadedJar = createShadedJarWithMultiplePomProperties("a-shaded-1.0.jar",
                "org.a", "a-shaded", "1.0",
                "com.example", "x", "1.0",
                "shaded-content");
        Artifact shadedArtifact = createArtifact("org.a", "a-shaded", "1.0", "jar", shadedJar.toFile());
        Path xJar = createJarWithPomProperties("x-1.0.jar", "com.example", "x", "1.0", "x-content");
        Path warFile = tempDir.resolve("war-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/x-1.0.jar"));
            jos.write(Files.readAllBytes(xJar));
            jos.closeEntry();
        }
        Artifact warArtifact = createArtifact("org.z", "war", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(new LinkedHashSet<>(List.of(shadedArtifact, warArtifact)));

        String xHash = SbomUtils.computeHash(digest, xJar);
        List<FileEntry> entries = List.of(
                new FileEntry("lib/a-shaded-1.0.jar", SbomUtils.computeHash(digest, shadedJar)),
                new FileEntry("web/war/WEB-INF/lib/x-1.0.jar", xHash));

        AssemblyComponents model = createAnalyzer().analyze(entries, null);

        PackageComponent war = extractPackageComponents(model).stream()
                .filter(c -> "war".equals(((ArtifactCoords) c.ref()).artifactId())).findFirst().orElseThrow();
        PackageComponent warX = (PackageComponent) war.nested().get(0);
        assertEquals("web/war/WEB-INF/lib/x-1.0.jar", warX.archivePath());
        assertEquals(xHash, warX.hash());
        assertTrue(warX.dependenciesKnown());
        PackageComponent shaded = extractPackageComponents(model).stream()
                .filter(c -> "a-shaded".equals(((ArtifactCoords) c.ref()).artifactId())).findFirst().orElseThrow();
        PackageComponent bundledX = (PackageComponent) shaded.nested().get(0);
        assertNull(bundledX.archivePath());
        assertFalse(bundledX.dependenciesKnown());
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
        assertTrue(jarFile.nested().stream().noneMatch(AssemblyComponent::dependenciesKnown),
                "artifacts known only from their pom.properties have unresolved dependencies");
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
        assertFalse(extractPackageComponents(model).get(0).dependenciesKnown(),
                "identified from its pom.properties, not a project dependency: dependencies never resolved");

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
            MavenArtifactMatcher resolver = createResolver(stub, List.of("**/*.jar"), List.of());
            ArchiveAnalyzer analyzer = createAnalyzerWithRemoteLookup(resolver);

            AssemblyComponents model = analyzer.analyze(List.of(
                    new FileEntry("lib/gradle-built-1.0.jar",
                            SbomUtils.computeHash(digest, jar), jar.toFile())),
                    null);

            List<PackageComponent> packages = extractPackageComponents(model);
            assertEquals(1, packages.size());
            ArtifactCoords coords = (ArtifactCoords) packages.get(0).ref();
            assertEquals(ArtifactCoords.of("org.gradle.example", "gradle-built", "1.0"), coords);
            assertEquals(Identification.remoteCoordinatesLookup(), packages.get(0).identification());
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
            MavenArtifactMatcher resolver = createResolver(
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

    @Test
    void unmatchedJarIdentifiedByMatcherCarriesTheMatchersIdentification() throws Exception {
        Path jar = createTestJar("custom-1.0.jar", "matcher-content");
        Identification custom = new Identification(Technique.OTHER, 0.42);
        MavenArtifactMatcher matcher = file -> Optional.of(
                new MavenMatch(ArtifactCoords.of("org.example", "custom", "1.0"), custom));

        AssemblyComponents model = createAnalyzerWithRemoteLookup(matcher).analyze(List.of(
                new FileEntry("lib/custom-1.0.jar", SbomUtils.computeHash(digest, jar), jar.toFile())), null);

        List<PackageComponent> packages = extractPackageComponents(model);
        assertEquals(1, packages.size());
        assertEquals(ArtifactCoords.of("org.example", "custom", "1.0"), packages.get(0).ref());
        assertEquals(custom, packages.get(0).identification());
        assertEquals(0, extractFileComponents(model).size());
    }

    @Test
    void bundledDepsSurviveWhenOwnerIsIdentifiedViaRemoteLookup() throws Exception {
        Path shadedJar = createShadedJarWithMultiplePomProperties("ab-cd-1.0.jar",
                "com.example", "ab", "1.0",
                "com.other", "cd", "2.0",
                "ambiguous-content");
        when(project.getArtifacts()).thenReturn(Set.of());
        String hash = SbomUtils.computeHash(digest, shadedJar);
        MavenArtifactMatcher resolver = file -> Optional.of(new MavenMatch(
                ArtifactCoords.of("org.gradle.example", "resolved", "9.0"), Identification.remoteComponentMatch(1)));

        AssemblyComponents model = createAnalyzerWithRemoteLookup(resolver).analyze(List.of(
                new FileEntry("lib/ab-cd-1.0.jar", hash, shadedJar.toFile())), null);

        assertEquals(0, extractFileComponents(model).size(),
                "owner identified remotely, so the jar is a package now, not a file component");
        List<PackageComponent> packages = extractPackageComponents(model);
        assertEquals(1, packages.size());
        assertEquals(ArtifactCoords.of("org.gradle.example", "resolved", "9.0"), packages.get(0).ref());
        assertFalse(packages.get(0).dependenciesKnown(), "identified remotely: dependencies never resolved");
        assertTrue(isNestedUnder(model, "ab", "resolved"),
                "bundled deps discovered before the remote match must nest under the now-known owner");
        assertTrue(isNestedUnder(model, "cd", "resolved"));
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

    private MavenArtifactMatcher createResolver(HttpServer stub, List<String> includes, List<String> excludes) {
        Nexus nexus = new Nexus();
        nexus.setIncludes(includes);
        nexus.setExcludes(excludes);
        nexus.setUrl("http://127.0.0.1:" + stub.getAddress().getPort()
                + "/service/rest/v1/search?sha1={sha1}");
        return MavenArtifactMatchers.create(List.of(nexus), false, serverId -> null).orElseThrow();
    }

    private ArchiveAnalyzer createAnalyzerWithRemoteLookup(MavenArtifactMatcher resolver) {
        return new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(), true, resolver);
    }

    // ---- Found-SBOM identification ----

    private Path createJarWithEntries(String name, Map<String, byte[]> entries) throws Exception {
        Path jarPath = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                jos.putNextEntry(new JarEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
        return jarPath;
    }

    private byte[] sbomJson(String purl, String hash, Method.Technique technique, double confidence)
            throws Exception {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setName("claimed");
        c.setPurl(purl);
        c.setBomRef(purl);
        c.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        Method method = new Method();
        method.setTechnique(technique);
        method.setConfidence(confidence);
        Identity identity = new Identity();
        identity.setField(Identity.Field.PURL);
        identity.setConfidence(confidence);
        identity.setMethods(List.of(method));
        Evidence evidence = new Evidence();
        evidence.setIdentities(new ArrayList<>(List.of(identity)));
        c.setEvidence(evidence);
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(c)));
        Path out = Files.createTempFile(tempDir, "sbom", ".cdx.json");
        BomWriter.writeJson(bom, out, false);
        return Files.readAllBytes(out);
    }

    private Path nimbusJar() throws Exception {
        Path nimbus = tempDir.resolve("nimbus-jose-jwt-10.6.jar");
        if (Files.exists(nimbus)) {
            return nimbus;
        }
        return createShadedJarWithMultiplePomProperties("nimbus-jose-jwt-10.6.jar",
                "com.nimbusds", "nimbus-jose-jwt", "10.6",
                "com.github.stephenc.jcip", "jcip-annotations", "1.0-1",
                "nimbus-content");
    }

    /** A resolved console war bundling a shaded nimbus jar and the given SBOM. */
    private List<FileEntry> setUpConsoleWarWithNimbus(byte[] sbomContent) throws Exception {
        Path nimbus = nimbusJar();
        Map<String, byte[]> warEntries = new LinkedHashMap<>();
        warEntries.put("WEB-INF/lib/nimbus-jose-jwt-10.6.jar", Files.readAllBytes(nimbus));
        warEntries.put("META-INF/sbom/bom.cdx.json", sbomContent);
        Path war = createJarWithEntries("console-1.0.war", warEntries);
        when(project.getArtifacts()).thenReturn(
                Set.of(createArtifact("org.example", "console", "1.0", "war", war.toFile())));
        return List.of(new FileEntry("web/console/WEB-INF/lib/nimbus-jose-jwt-10.6.jar",
                SbomUtils.computeHash(digest, nimbus)));
    }

    /** The console war whose SBOM claims the nimbus jar's hash as nimbus at the given version. */
    private List<FileEntry> consoleWarWithNimbusSbom(String claimedVersion) throws Exception {
        String hash = SbomUtils.computeHash(digest, nimbusJar());
        return setUpConsoleWarWithNimbus(sbomJson("pkg:maven/com.nimbusds/nimbus-jose-jwt@" + claimedVersion,
                hash, Method.Technique.HASH_COMPARISON, 1.0));
    }

    private PackageComponent nestedPackage(AssemblyComponents model, String artifactId) {
        return extractNestedPackages(model).stream()
                .filter(p -> p.ref() instanceof ArtifactCoords c && artifactId.equals(c.artifactId()))
                .findFirst().orElseThrow(() -> new AssertionError("no nested " + artifactId));
    }

    @Test
    void foundSbomIdentifiesNestedShadedJarBeforePomProperties() throws Exception {
        List<FileEntry> entries = consoleWarWithNimbusSbom("10.6");

        AssemblyComponents model = createAnalyzer().analyze(entries, null);

        PackageComponent nimbus = nestedPackage(model, "nimbus-jose-jwt");
        assertEquals(new Identification(Technique.HASH_COMPARISON, 1.0), nimbus.identification());
        assertTrue(containsNestedWithArtifactId(nimbus, "jcip-annotations"), "bundled jcip must stay nested under nimbus");
        assertEquals(Identification.pomProperties(), nestedPackage(model, "jcip-annotations").identification());
    }

    @Test
    void foundSbomRejectedOnVersionMismatch() throws Exception {
        List<FileEntry> entries = consoleWarWithNimbusSbom("10.5");

        AssemblyComponents model = createAnalyzer().analyze(entries, null);

        PackageComponent nimbus = nestedPackage(model, "nimbus-jose-jwt");
        assertEquals("10.6", ((ArtifactCoords) nimbus.ref()).version());
        assertEquals(Identification.pomPropertiesFilenameOwner(), nimbus.identification());
    }

    @Test
    void unparsableFoundSbomFallsBackToPomProperties() throws Exception {
        List<FileEntry> entries = setUpConsoleWarWithNimbus("{not json".getBytes(StandardCharsets.UTF_8));

        AssemblyComponents model = createAnalyzer().analyze(entries, null);

        assertEquals(Identification.pomPropertiesFilenameOwner(),
                nestedPackage(model, "nimbus-jose-jwt").identification());
    }

    @Test
    void foundSbomIgnoredWhenEmbeddedSbomsIgnored() throws Exception {
        List<FileEntry> entries = consoleWarWithNimbusSbom("10.6");

        AssemblyComponents model = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(), false).analyze(entries, null);

        assertEquals(Identification.pomPropertiesFilenameOwner(),
                nestedPackage(model, "nimbus-jose-jwt").identification());
    }

    @Test
    void sbomIdentifiedNestedJarHonoursIdentityEvidenceOff() throws Exception {
        List<FileEntry> entries = consoleWarWithNimbusSbom("10.6");
        ArchiveAnalyzer analyzer = createAnalyzer();
        analyzer.setIdentityEvidence(false);

        AssemblyComponents model = analyzer.analyze(entries, null);

        PackageComponent nimbus = nestedPackage(model, "nimbus-jose-jwt");
        assertEquals(ArtifactCoords.of("com.nimbusds", "nimbus-jose-jwt", "10.6"), nimbus.ref());
        assertNull(nimbus.identification());
    }

    /** A resolved plain jar carrying an SBOM that claims the given hash as the given purl. */
    private Artifact carrierWithSbom(String purl, String hash) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("data.txt", "carrier".getBytes(StandardCharsets.UTF_8));
        entries.put("META-INF/sbom/bom.cdx.json", sbomJson(purl, hash, Method.Technique.HASH_COMPARISON, 1.0));
        Path carrier = createJarWithEntries("carrier-1.0.jar", entries);
        return createArtifact("org.example", "carrier", "1.0", "jar", carrier.toFile());
    }

    private FileEntry carrierEntry(Artifact carrier) throws Exception {
        return new FileEntry("lib/carrier-1.0.jar", SbomUtils.computeHash(digest, carrier.getFile().toPath()));
    }

    private PackageComponent topLevelPackage(AssemblyComponents model, String artifactId) {
        return extractPackageComponents(model).stream()
                .filter(p -> p.ref() instanceof ArtifactCoords c && artifactId.equals(c.artifactId()))
                .findFirst().orElseThrow(() -> new AssertionError("no top-level " + artifactId));
    }

    private boolean hasTopLevelPackage(AssemblyComponents model, String artifactId) {
        return extractPackageComponents(model).stream()
                .anyMatch(p -> p.ref() instanceof ArtifactCoords c && artifactId.equals(c.artifactId()));
    }

    private static Bom externalBomClaiming(String purl, String hash) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setName("external");
        c.setPurl(purl);
        c.setBomRef(purl);
        c.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(c)));
        return bom;
    }

    @Test
    void foundSbomIdentifiesTopLevelShadedJar() throws Exception {
        Path shaded = createShadedJarWithMultiplePomProperties("lib-z-3.0.jar",
                "org.example", "lib-z", "3.0",
                "com.bundled", "shaded-a", "1.5",
                "shaded-content");
        String hash = SbomUtils.computeHash(digest, shaded);
        Artifact carrier = carrierWithSbom("pkg:maven/org.example/lib-z@3.0", hash);
        when(project.getArtifacts()).thenReturn(Set.of(carrier));

        AssemblyComponents model = createAnalyzer().analyze(List.of(carrierEntry(carrier),
                new FileEntry("lib/lib-z-3.0.jar", hash, shaded.toFile())), null);

        PackageComponent libZ = topLevelPackage(model, "lib-z");
        assertEquals(new Identification(Technique.HASH_COMPARISON, 1.0), libZ.identification());
        assertFalse(libZ.dependenciesKnown(), "identified by a found SBOM: dependencies never resolved");
        assertTrue(containsNestedWithArtifactId(libZ, "shaded-a"));
        assertEquals(Identification.pomProperties(), nestedPackage(model, "shaded-a").identification());
    }

    @Test
    void foundSbomHashClaimForJarWithoutOwnDescriptorKeepsConfidence() throws Exception {
        Path fat = createJarWithPomProperties("fat-2.0.jar", "com.bundled", "shaded-x", "1.1", "fat-content");
        String hash = SbomUtils.computeHash(digest, fat);
        Artifact carrier = carrierWithSbom("pkg:maven/org.example/fat@2.0", hash);
        when(project.getArtifacts()).thenReturn(Set.of(carrier));

        AssemblyComponents model = createAnalyzer().analyze(List.of(carrierEntry(carrier),
                new FileEntry("lib/fat-2.0.jar", hash, fat.toFile())), null);

        PackageComponent fatPkg = topLevelPackage(model, "fat");
        assertEquals(ArtifactCoords.of("org.example", "fat", "2.0"), fatPkg.ref());
        assertEquals(new Identification(Technique.HASH_COMPARISON, 1.0), fatPkg.identification());
        assertTrue(containsNestedWithArtifactId(fatPkg, "shaded-x"));
        assertEquals(Identification.pomProperties(), nestedPackage(model, "shaded-x").identification());
    }

    @Test
    void externalSbomClaimsEntryBeforePomProperties() throws Exception {
        Path jar = createJarWithPomProperties("h2-2.4.jar", "com.h2database", "h2", "2.4", "h2-content");
        String hash = SbomUtils.computeHash(digest, jar);
        when(project.getArtifacts()).thenReturn(Set.of());
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", hash);

        AssemblyComponents model = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(external), true).analyze(
                        List.of(new FileEntry("lib/h2-2.4.jar", hash, jar.toFile())), null);

        assertFalse(hasTopLevelPackage(model, "h2"), "the external SBOM, not pom.properties, identifies it");
        List<Occurrence> occs = external.getComponents().get(0).getEvidence().getOccurrences();
        assertEquals("lib/h2-2.4.jar", occs.get(0).getLocation());
    }

    @Test
    void externalSbomWinsOverFoundSbom() throws Exception {
        Path jar = createJarWithPomProperties("h2-2.4.jar", "com.h2database", "h2", "2.4", "h2-content");
        String hash = SbomUtils.computeHash(digest, jar);
        Artifact carrier = carrierWithSbom("pkg:maven/com.h2database/h2@2.4", hash);
        when(project.getArtifacts()).thenReturn(Set.of(carrier));
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", hash);

        AssemblyComponents model = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(external), true).analyze(
                        List.of(carrierEntry(carrier),
                                new FileEntry("lib/h2-2.4.jar", hash, jar.toFile())),
                        null);

        assertFalse(hasTopLevelPackage(model, "h2"), "the external SBOM claims the entry first");
        assertEquals("lib/h2-2.4.jar",
                external.getComponents().get(0).getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void mavenHashMatchWinsOverFoundSbom() throws Exception {
        Path jar = createTestJar("lib-a-1.0.jar", "content-a");
        String hash = SbomUtils.computeHash(digest, jar);
        Artifact libA = createArtifact("org.example", "lib-a", "1.0", "jar", jar.toFile());
        Artifact carrier = carrierWithSbom("pkg:maven/other/other@9", hash);
        when(project.getArtifacts()).thenReturn(Set.of(libA, carrier));

        AssemblyComponents model = createAnalyzer().analyze(List.of(carrierEntry(carrier),
                new FileEntry("lib/lib-a-1.0.jar", hash)), null);

        assertEquals(Identification.hashMatch(), topLevelPackage(model, "lib-a").identification());
        assertFalse(hasTopLevelPackage(model, "other"));
    }

    @Test
    void foundSbomNestedOwnerWithoutOwnDescriptorKeepsBundled() throws Exception {
        Path fat = createJarWithPomProperties("fat-2.0.jar", "com.bundled", "shaded-x", "1.1", "fat-content");
        String hash = SbomUtils.computeHash(digest, fat);
        Map<String, byte[]> warEntries = new LinkedHashMap<>();
        warEntries.put("WEB-INF/lib/fat-2.0.jar", Files.readAllBytes(fat));
        warEntries.put("META-INF/sbom/bom.cdx.json",
                sbomJson("pkg:maven/org.example/fat@2.0", hash, Method.Technique.HASH_COMPARISON, 1.0));
        Path war = createJarWithEntries("console-1.0.war", warEntries);
        when(project.getArtifacts()).thenReturn(
                Set.of(createArtifact("org.example", "console", "1.0", "war", war.toFile())));

        AssemblyComponents model = createAnalyzer().analyze(
                List.of(new FileEntry("web/console/WEB-INF/lib/fat-2.0.jar", hash)), null);

        PackageComponent fatPkg = nestedPackage(model, "fat");
        assertEquals(new Identification(Technique.HASH_COMPARISON, 1.0), fatPkg.identification());
        assertTrue(containsNestedWithArtifactId(fatPkg, "shaded-x"),
                "the jar's only descriptor is a bundled artifact, not the owner");
    }

    // ---- merge selection and configured-SBOM scope ----

    /** A resolved jar holding an SBOM, so merge selection has something to pick. */
    private Artifact jarWithSbom(String fileName, String groupId, String artifactId) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("data.txt", fileName.getBytes(StandardCharsets.UTF_8));
        entries.put("META-INF/sbom/bom.cdx.json",
                sbomJson("pkg:npm/x@1.0", "00", Method.Technique.HASH_COMPARISON, 1.0));
        Path jar = createJarWithEntries(fileName, entries);
        return createArtifact(groupId, artifactId, "1.0", "jar", jar.toFile());
    }

    @Test
    void embeddedSbomOfUnshippedArtifactIsNotMerged() throws Exception {
        Artifact shipped = jarWithSbom("shipped-1.0.jar", "org.example", "shipped");
        Artifact unshipped = jarWithSbom("unshipped-1.0.jar", "org.example", "unshipped");
        when(project.getArtifacts()).thenReturn(new LinkedHashSet<>(List.of(shipped, unshipped)));

        AssemblyComponents model = createAnalyzer().analyze(List.of(new FileEntry("lib/shipped-1.0.jar",
                SbomUtils.computeHash(digest, shipped.getFile().toPath()))), null);

        assertEquals(List.of(ArtifactCoords.of("org.example", "shipped", "1.0")),
                model.discoveredSboms().stream().map(DiscoveredSbom::owner).toList());
    }

    @Test
    void embeddedSbomOfSharedFileOwnedByFirstArtifact() throws Exception {
        Artifact first = jarWithSbom("shared-1.0.jar", "org.example", "first");
        Artifact second = createArtifact("org.example", "second", "1.0", "jar", first.getFile());
        when(project.getArtifacts()).thenReturn(new LinkedHashSet<>(List.of(first, second)));

        AssemblyComponents model = createAnalyzer().analyze(List.of(new FileEntry("lib/shared-1.0.jar",
                SbomUtils.computeHash(digest, first.getFile().toPath()))), null);

        assertEquals(List.of(ArtifactCoords.of("org.example", "first", "1.0")),
                model.discoveredSboms().stream().map(DiscoveredSbom::owner).toList(),
                "one file's SBOMs are recorded once, under the first artifact");
    }

    @Test
    void configuredExternalSbomNotConsultedForJarNestedInUnpackedArtifact() throws Exception {
        Path h2 = createJarWithPomProperties("h2-2.4.jar", "com.h2database", "h2", "2.4", "h2-content");
        String hash = SbomUtils.computeHash(digest, h2);
        Path war = createJarWithEntries("app-1.0.war", Map.of("WEB-INF/lib/h2-2.4.jar", Files.readAllBytes(h2)));
        when(project.getArtifacts()).thenReturn(
                Set.of(createArtifact("org.example", "app", "1.0", "war", war.toFile())));
        Bom external = externalBomClaiming("pkg:maven/com.example/other@1.0", hash);

        AssemblyComponents model = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(external), true).analyze(
                        List.of(new FileEntry("web/app/WEB-INF/lib/h2-2.4.jar", hash)), null);

        assertEquals(Identification.pomProperties(), nestedPackage(model, "h2").identification());
        assertNull(external.getComponents().get(0).getEvidence(),
                "the external component did not claim the nested jar");
    }

    // ---- configured external Maven claims cross-checked with pom.properties ----

    private record H2Jar(Path jar, String hash, FileEntry entry) {
    }

    private H2Jar h2Jar() throws Exception {
        Path jar = createJarWithPomProperties("h2-2.4.jar", "com.h2database", "h2", "2.4", "h2-content");
        String hash = SbomUtils.computeHash(digest, jar);
        return new H2Jar(jar, hash, new FileEntry("lib/h2-2.4.jar", hash, jar.toFile()));
    }

    private AssemblyComponents analyzeWithExternal(Bom external, FileEntry entry, boolean identityEvidence) {
        when(project.getArtifacts()).thenReturn(Set.of());
        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(effectiveModelResolver, repoSystem, project, session,
                digest, false, List.of(external), true);
        analyzer.setIdentityEvidence(identityEvidence);
        return analyzer.analyze(List.of(entry), null);
    }

    private static List<Identity> identities(Component c) {
        return c.getEvidence() == null || c.getEvidence().getIdentities() == null
                ? List.of()
                : c.getEvidence().getIdentities();
    }

    @Test
    void externalMavenClaimConfirmedByPomPropertiesGainsManifestIdentity() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", h2.hash());

        analyzeWithExternal(external, h2.entry(), true);

        Component c = external.getComponents().get(0);
        assertEquals(1, identities(c).size());
        Identity id = identities(c).get(0);
        assertEquals(Identity.Field.PURL, id.getField());
        assertEquals(1.0, id.getConfidence());
        assertEquals(Method.Technique.MANIFEST_ANALYSIS, id.getMethods().get(0).getTechnique());
        assertEquals("lib/h2-2.4.jar", c.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void externalMavenClaimKeepsItsOwnIdentity() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", h2.hash());
        Method method = new Method();
        method.setTechnique(Method.Technique.HASH_COMPARISON);
        method.setConfidence(0.9);
        Identity own = new Identity();
        own.setField(Identity.Field.PURL);
        own.setConfidence(0.9);
        own.setMethods(List.of(method));
        Evidence evidence = new Evidence();
        evidence.setIdentities(new ArrayList<>(List.of(own)));
        external.getComponents().get(0).setEvidence(evidence);

        analyzeWithExternal(external, h2.entry(), true);

        assertEquals(List.of(own), identities(external.getComponents().get(0)));
    }

    @Test
    void externalMavenClaimRejectedOnVersionMismatch() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.3", h2.hash());

        AssemblyComponents model = analyzeWithExternal(external, h2.entry(), true);

        PackageComponent pkg = topLevelPackage(model, "h2");
        assertEquals(ArtifactCoords.of("com.h2database", "h2", "2.4"), pkg.ref());
        assertEquals(Identification.pomProperties(), pkg.identification());
        assertNull(external.getComponents().get(0).getEvidence(), "the contradicted claim is not used");
    }

    @Test
    void externalMavenClaimWithoutOwnDescriptorGainsNoIdentity() throws Exception {
        Path fat = createJarWithPomProperties("fat-2.0.jar", "com.bundled", "shaded-x", "1.1", "fat-content");
        String hash = SbomUtils.computeHash(digest, fat);
        Bom external = externalBomClaiming("pkg:maven/org.example/fat@2.0", hash);

        AssemblyComponents model = analyzeWithExternal(external,
                new FileEntry("lib/fat-2.0.jar", hash, fat.toFile()), true);

        assertFalse(hasTopLevelPackage(model, "fat"));
        assertTrue(identities(external.getComponents().get(0)).isEmpty(), "nothing in the jar confirms it");
        assertEquals("lib/fat-2.0.jar",
                external.getComponents().get(0).getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void externalNonMavenClaimGainsNoIdentity() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:npm/h2@2.4", h2.hash());

        analyzeWithExternal(external, h2.entry(), true);

        assertTrue(identities(external.getComponents().get(0)).isEmpty());
    }

    @Test
    void externalMavenClaimGainsNoIdentityWhenIdentityEvidenceOff() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", h2.hash());

        analyzeWithExternal(external, h2.entry(), false);

        assertTrue(identities(external.getComponents().get(0)).isEmpty());
    }

    private static Component bundledEntry(String purl) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setName("bundled");
        c.setPurl(purl);
        c.setBomRef(purl + "#bundled");
        return c;
    }

    @Test
    void externalClaimNestedEntriesConfirmedByBundledDescriptorsGainManifestIdentity() throws Exception {
        Path shaded = createShadedJarWithMultiplePomProperties("lib-z-3.0.jar",
                "org.example", "lib-z", "3.0",
                "com.bundled", "shaded-a", "1.5",
                "shaded-content");
        String hash = SbomUtils.computeHash(digest, shaded);
        Bom external = externalBomClaiming("pkg:maven/org.example/lib-z@3.0?type=jar", hash);
        Component confirmed = bundledEntry("pkg:maven/com.bundled/shaded-a@1.5?type=jar");
        Component unconfirmed = bundledEntry("pkg:maven/com.bundled/other@1.0?type=jar");
        external.getComponents().get(0).setComponents(new ArrayList<>(List.of(confirmed, unconfirmed)));

        analyzeWithExternal(external, new FileEntry("lib/lib-z-3.0.jar", hash, shaded.toFile()), true);

        assertEquals(1, identities(external.getComponents().get(0)).size(), "the owner is confirmed");
        assertEquals(Method.Technique.MANIFEST_ANALYSIS,
                identities(confirmed).get(0).getMethods().get(0).getTechnique());
        assertTrue(identities(unconfirmed).isEmpty(), "no descriptor in the jar declares it");
    }

    @Test
    void externalClaimNestedEntryConfirmedEvenWhenOwnerDescriptorMissing() throws Exception {
        Path fat = createJarWithPomProperties("fat-2.0.jar", "com.bundled", "shaded-x", "1.1", "fat-content");
        String hash = SbomUtils.computeHash(digest, fat);
        Bom external = externalBomClaiming("pkg:maven/org.example/fat@2.0", hash);
        Component bundled = bundledEntry("pkg:maven/com.bundled/shaded-x@1.1");
        external.getComponents().get(0).setComponents(new ArrayList<>(List.of(bundled)));

        analyzeWithExternal(external, new FileEntry("lib/fat-2.0.jar", hash, fat.toFile()), true);

        assertTrue(identities(external.getComponents().get(0)).isEmpty(), "nothing in the jar confirms the owner");
        assertEquals(1, identities(bundled).size(), "its own descriptor confirms the bundled entry");
    }

    @Test
    void externalClaimNestedEntriesGainNoIdentityWhenIdentityEvidenceOff() throws Exception {
        Path shaded = createShadedJarWithMultiplePomProperties("lib-z-3.0.jar",
                "org.example", "lib-z", "3.0",
                "com.bundled", "shaded-a", "1.5",
                "shaded-content");
        String hash = SbomUtils.computeHash(digest, shaded);
        Bom external = externalBomClaiming("pkg:maven/org.example/lib-z@3.0", hash);
        Component bundled = bundledEntry("pkg:maven/com.bundled/shaded-a@1.5");
        external.getComponents().get(0).setComponents(new ArrayList<>(List.of(bundled)));

        analyzeWithExternal(external, new FileEntry("lib/lib-z-3.0.jar", hash, shaded.toFile()), false);

        assertTrue(identities(bundled).isEmpty());
    }

    @Test
    void rejectedExternalMavenClaimIsReportedForRemoval() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.3", h2.hash());
        when(project.getArtifacts()).thenReturn(Set.of());
        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(effectiveModelResolver, repoSystem, project, session,
                digest, false, List.of(external), true);

        analyzer.analyze(List.of(h2.entry()), null);

        assertEquals(1, analyzer.rejectedExternalComponents().size());
        assertSame(external.getComponents().get(0), analyzer.rejectedExternalComponents().iterator().next());
    }

    @Test
    void acceptedExternalClaimIsNotReportedForRemoval() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", h2.hash());
        when(project.getArtifacts()).thenReturn(Set.of());
        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(effectiveModelResolver, repoSystem, project, session,
                digest, false, List.of(external), true);

        analyzer.analyze(List.of(h2.entry()), null);

        assertTrue(analyzer.rejectedExternalComponents().isEmpty());
    }

    // ---- bundled descriptors of externally claimed shaded jars ----

    private record ShadedLibZ(String hash, FileEntry entry) {
    }

    private ShadedLibZ shadedLibZ() throws Exception {
        Path shaded = createShadedJarWithMultiplePomProperties("lib-z-3.0.jar",
                "org.example", "lib-z", "3.0",
                "com.bundled", "shaded-a", "1.5",
                "shaded-content");
        String hash = SbomUtils.computeHash(digest, shaded);
        return new ShadedLibZ(hash, new FileEntry("lib/lib-z-3.0.jar", hash, shaded.toFile()));
    }

    private static List<String> nestedPurls(Component c) {
        return c.getComponents() == null ? List.of()
                : c.getComponents().stream().map(Component::getPurl).toList();
    }

    @Test
    void externalShadedClaimGainsUnlistedBundledDescriptors() throws Exception {
        ShadedLibZ jar = shadedLibZ();
        Bom external = externalBomClaiming("pkg:maven/org.example/lib-z@3.0", jar.hash());

        analyzeWithExternal(external, jar.entry(), true);

        Component owner = external.getComponents().get(0);
        assertEquals(List.of("pkg:maven/com.bundled/shaded-a@1.5"), nestedPurls(owner));
        Component bundled = owner.getComponents().get(0);
        assertEquals(Component.Type.LIBRARY, bundled.getType());
        assertEquals("com.bundled", bundled.getGroup());
        assertEquals("shaded-a", bundled.getName());
        assertEquals("1.5", bundled.getVersion());
        assertEquals(Method.Technique.MANIFEST_ANALYSIS, identities(bundled).get(0).getMethods().get(0).getTechnique());
    }

    @Test
    void externalShadedClaimDoesNotDuplicateListedBundledEntry() throws Exception {
        ShadedLibZ jar = shadedLibZ();
        Bom external = externalBomClaiming("pkg:maven/org.example/lib-z@3.0", jar.hash());
        external.getComponents().get(0).setComponents(new ArrayList<>(List.of(
                bundledEntry("pkg:maven/com.bundled/shaded-a@1.5?type=jar"))));

        analyzeWithExternal(external, jar.entry(), true);

        assertEquals(List.of("pkg:maven/com.bundled/shaded-a@1.5?type=jar"),
                nestedPurls(external.getComponents().get(0)));
    }

    @Test
    void externalShadedClaimBundledAddedWithoutIdentityWhenIdentityEvidenceOff() throws Exception {
        ShadedLibZ jar = shadedLibZ();
        Bom external = externalBomClaiming("pkg:maven/org.example/lib-z@3.0", jar.hash());

        analyzeWithExternal(external, jar.entry(), false);

        Component owner = external.getComponents().get(0);
        assertEquals(List.of("pkg:maven/com.bundled/shaded-a@1.5"), nestedPurls(owner));
        assertTrue(identities(owner.getComponents().get(0)).isEmpty());
    }

    @Test
    void externalMavenIdentityAppendedKeepingNonPurlIdentities() throws Exception {
        H2Jar h2 = h2Jar();
        Bom external = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", h2.hash());
        Identity name = new Identity();
        name.setField(Identity.Field.NAME);
        name.setConfidence(0.4);
        Evidence evidence = new Evidence();
        evidence.setIdentities(new ArrayList<>(List.of(name)));
        external.getComponents().get(0).setEvidence(evidence);

        analyzeWithExternal(external, h2.entry(), true);

        List<Identity> ids = identities(external.getComponents().get(0));
        assertEquals(List.of(Identity.Field.NAME, Identity.Field.PURL), ids.stream().map(Identity::getField).toList());
    }

    @Test
    void configuredExternalCrossCheckWorksWithEmbeddedSbomsIgnored() throws Exception {
        H2Jar h2 = h2Jar();
        Bom confirmedBom = externalBomClaiming("pkg:maven/com.h2database/h2@2.4", h2.hash());
        when(project.getArtifacts()).thenReturn(Set.of());
        new ArchiveAnalyzer(effectiveModelResolver, repoSystem, project, session, digest,
                false, List.of(confirmedBom), false).analyze(List.of(h2.entry()), null);
        assertEquals(1, identities(confirmedBom.getComponents().get(0)).size());

        Bom mismatchBom = externalBomClaiming("pkg:maven/com.h2database/h2@2.3", h2.hash());
        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(effectiveModelResolver, repoSystem, project, session,
                digest, false, List.of(mismatchBom), false);
        AssemblyComponents model = analyzer.analyze(List.of(h2.entry()), null);
        assertEquals(Identification.pomProperties(), topLevelPackage(model, "h2").identification());
        assertEquals(1, analyzer.rejectedExternalComponents().size());
    }
}
