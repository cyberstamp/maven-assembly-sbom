package io.github.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.File;
import java.lang.reflect.Field;
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
import org.apache.maven.model.Build;
import org.apache.maven.model.License;
import org.apache.maven.model.Model;
import org.apache.maven.model.Plugin;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.codehaus.plexus.archiver.ArchiverException;
import org.codehaus.plexus.archiver.zip.ZipArchiver;
import org.codehaus.plexus.components.io.fileselectors.FileInfo;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.CollectResult;
import org.eclipse.aether.collection.DependencyCollectionContext;
import org.eclipse.aether.collection.DependencySelector;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SbomContainerDescriptorHandlerTest {

    @TempDir
    Path tempDir;

    @Mock
    MavenProject project;

    @Mock
    MavenSession session;

    @Mock
    RepositorySystem repoSystem;

    @Mock
    RepositorySystemSession repoSession;

    @Mock
    EffectiveModelResolver effectiveModelResolver;

    @Mock
    MavenProjectHelper projectHelper;

    private SbomContainerDescriptorHandler handler;

    @BeforeEach
    void setUp() throws Exception {
        handler = new SbomContainerDescriptorHandler();
        setField(handler, "project", project);
        setField(handler, "session", session);
        setField(handler, "repoSystem", repoSystem);
        setField(handler, "effectiveModelResolver", effectiveModelResolver);
        setField(handler, "projectHelper", projectHelper);

        lenient().when(project.getGroupId()).thenReturn("com.example");
        lenient().when(project.getArtifactId()).thenReturn("test-app");
        lenient().when(project.getVersion()).thenReturn("1.0");
        Build build = new Build();
        build.setDirectory(tempDir.resolve("target").toString());
        lenient().when(project.getBuild()).thenReturn(build);
        lenient().when(effectiveModelResolver.resolveEffectiveModel(
                "com.example", "test-app", "1.0")).thenReturn(null);
        lenient().when(session.getRepositorySession()).thenReturn(repoSession);
        DependencySelector defaultSelector = mock(DependencySelector.class);
        lenient().when(defaultSelector.selectDependency(any())).thenReturn(true);
        lenient().when(defaultSelector.deriveChildSelector(any())).thenReturn(defaultSelector);
        lenient().when(repoSession.getDependencySelector()).thenReturn(defaultSelector);
        lenient().when(session.getProjects()).thenReturn(List.of());
    }

    @Test
    void isSelectedAlwaysReturnsTrue() throws Exception {
        FileInfo fileInfo = mock(FileInfo.class);
        assertTrue(handler.isSelected(fileInfo));
    }

    @Test
    void artifactMatchedByFilename() throws Exception {
        Path jarFile = createTestJar("foo-1.0.jar", "hello");
        Artifact artifact = createArtifact("org.example", "foo", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        ZipArchiver archiver = buildArchiver("base/lib/foo-1.0.jar", jarFile);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component lib = findComponent(bom, Component.Type.LIBRARY, "foo");
        assertNotNull(lib, "should find foo as LIBRARY");
        assertEquals("pkg:maven/org.example/foo@1.0", lib.getPurl());
        assertEquals("lib/foo-1.0.jar",
                lib.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void artifactMatchedByHash() throws Exception {
        Path jarFile = createTestJar("foo-1.0.jar", "unique-content-for-hash-match");
        Artifact artifact = createArtifact("org.example", "foo", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        ZipArchiver archiver = buildArchiver("base/lib/renamed.jar", jarFile);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component lib = findComponent(bom, Component.Type.LIBRARY, "foo");
        assertNotNull(lib, "should match by SHA-256 even with different filename");
    }

    @Test
    void unmatchedFileBecomesFileComponent() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("app.properties", "key=value");

        ZipArchiver archiver = buildArchiver("base/conf/app.properties", props);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component file = findComponent(bom, Component.Type.FILE, "app.properties");
        assertNotNull(file, "unmatched file should be FILE component");
        assertTrue(file.getPurl().startsWith("pkg:generic/app.properties"));
    }

    @Test
    void baseDirectoryStripped() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("app.properties", "key=value");

        ZipArchiver archiver = buildArchiver("myapp-1.0/conf/app.properties", props);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component file = findComponent(bom, Component.Type.FILE, "app.properties");
        assertNotNull(file);
        assertEquals("conf/app.properties",
                file.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void bomAddedInsideArchive() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("app.properties", "data");

        ZipArchiver archiver = buildArchiver("base/conf/app.properties", props);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        assertNotNull(bom, "BOM should be added to the archive");
    }

    @Test
    void xmlFormatOutput() throws Exception {
        handler.setOutputMode("external");
        handler.setFormat("xml");
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("data.txt", "hello");

        Path archivePath = tempDir.resolve("test-xml.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(props.toFile(), "base/data.txt");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("test-xml.zip.cdx.xml");
        assertTrue(Files.exists(bomFile));
        String content = Files.readString(bomFile);
        assertTrue(content.contains("<bom"));
    }

    @Test
    void unpackedArtifactDetectedByDigest() throws Exception {
        Path entryContent = createTestFile("entry.txt", "unpacked-entry-content");
        byte[] entryBytes = Files.readAllBytes(entryContent);

        Path jarFile = tempDir.resolve("mywar-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/entry.txt"));
            jos.write(entryBytes);
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "mywar", "1.0", "war", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        ZipArchiver archiver = buildArchiver("base/web/entry.txt", entryContent);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component lib = findComponent(bom, Component.Type.LIBRARY, "mywar");
        assertNotNull(lib, "unpacked WAR should be detected as LIBRARY via digest match");
        assertTrue(lib.getPurl().contains("type=war"));
    }

    @Test
    void dependencyGraphIncluded() throws Exception {
        Path jarA = createTestJar("a-1.0.jar", "content-a");
        Path jarB = createTestJar("b-1.0.jar", "content-b");
        Artifact artifactA = createArtifact("org.x", "a", "1.0", "jar", jarA.toFile());
        Artifact artifactB = createArtifact("org.x", "b", "1.0", "jar", jarB.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifactA, artifactB));
        when(project.getDependencies()).thenReturn(List.of());

        org.eclipse.aether.artifact.Artifact aetherA = new org.eclipse.aether.artifact.DefaultArtifact("org.x", "a", "jar",
                "1.0");
        org.eclipse.aether.artifact.Artifact aetherB = new org.eclipse.aether.artifact.DefaultArtifact("org.x", "b", "jar",
                "1.0");
        Dependency depA = new Dependency(aetherA, "compile");
        Dependency depB = new Dependency(aetherB, "compile");

        when(repoSystem.collectDependencies(any(RepositorySystemSession.class), any())).thenAnswer(invocation -> {
            RepositorySystemSession sess = invocation.getArgument(0);
            DependencySelector selector = sess.getDependencySelector();

            var rootCtx = mockCollectionContext(
                    new org.eclipse.aether.artifact.DefaultArtifact(
                            "com.example", "test-app", "jar", "1.0"),
                    null);
            DependencySelector rootChild = selector.deriveChildSelector(rootCtx);
            rootChild.selectDependency(depA);

            var aCtx = mockCollectionContext(aetherA, depA);
            DependencySelector aChild = rootChild.deriveChildSelector(aCtx);
            aChild.selectDependency(depB);

            DefaultDependencyNode root = new DefaultDependencyNode((Dependency) null);
            root.setChildren(List.of());
            CollectResult result = new CollectResult(invocation.getArgument(1));
            result.setRoot(root);
            return result;
        });

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("out.zip").toFile());
        archiver.addFile(jarA.toFile(), "base/lib/a-1.0.jar");
        archiver.addFile(jarB.toFile(), "base/lib/b-1.0.jar");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        String refA = "pkg:maven/org.x/a@1.0";
        String refB = "pkg:maven/org.x/b@1.0";
        var bomDepA = bom.getDependencies().stream()
                .filter(d -> refA.equals(d.getRef())).findFirst().orElse(null);
        assertNotNull(bomDepA);
        assertTrue(bomDepA.getDependencies().stream().anyMatch(d -> refB.equals(d.getRef())),
                "a should depend on b");
    }

    @Test
    void duplicateArtifactAtTwoLocationsMergesOccurrences() throws Exception {
        Path jarFile = createTestJar("jspecify-1.0.jar", "jspecify-content");
        Artifact artifact = createArtifact("org.jspecify", "jspecify", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("test.zip").toFile());
        archiver.addFile(jarFile.toFile(), "base/lib/jspecify-1.0.jar");
        archiver.addFile(jarFile.toFile(), "base/web/console.war/WEB-INF/lib/jspecify-1.0.jar");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        long libCount = bom.getComponents().stream()
                .filter(c -> c.getType() == Component.Type.LIBRARY && "jspecify".equals(c.getName()))
                .count();
        assertEquals(1, libCount, "same artifact should appear once");

        Component comp = findComponent(bom, Component.Type.LIBRARY, "jspecify");
        assertEquals(2, comp.getEvidence().getOccurrences().size(),
                "should have two occurrences");
    }

    @Test
    void unpackedWarNestedJarsBecomeLibraries() throws Exception {
        Path nestedJar = createTestJar("nested-lib-2.0.jar", "nested-content");
        Path htmlFile = createTestFile("index.html", "<html>hello</html>");

        Path warFile = tempDir.resolve("console-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/nested-lib-2.0.jar"));
            jos.write(Files.readAllBytes(nestedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("index.html"));
            jos.write(Files.readAllBytes(htmlFile));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "console", "1.0", "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        MavenProject consoleProject = mock(MavenProject.class);
        when(consoleProject.getGroupId()).thenReturn("org.example");
        when(consoleProject.getArtifactId()).thenReturn("console");
        when(consoleProject.getVersion()).thenReturn("1.0");
        when(consoleProject.getPackaging()).thenReturn("war");

        Artifact nestedArtifact = createArtifact("org.nested", "nested-lib", "2.0",
                "jar", nestedJar.toFile());
        when(consoleProject.getArtifacts()).thenReturn(Set.of(nestedArtifact));
        when(session.getProjects()).thenReturn(List.of(consoleProject));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("out.zip").toFile());
        archiver.addFile(nestedJar.toFile(),
                "base/web/console.war/WEB-INF/lib/nested-lib-2.0.jar");
        archiver.addFile(htmlFile.toFile(), "base/web/console.war/index.html");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        Component war = findComponent(bom, Component.Type.LIBRARY, "console");
        assertNotNull(war, "WAR should be detected as LIBRARY");
        assertTrue(war.getPurl().contains("type=war"));
        assertEquals("web/console.war/",
                war.getEvidence().getOccurrences().get(0).getLocation(),
                "WAR occurrence should be the unpack location");

        assertNull(findComponent(bom, Component.Type.LIBRARY, "nested-lib"),
                "nested JAR should NOT appear as top-level component");
        assertNotNull(war.getComponents(), "WAR should have nested components");
        assertEquals(1, war.getComponents().size());
        Component nested = war.getComponents().get(0);
        assertEquals("nested-lib", nested.getName());
        assertEquals("pkg:maven/org.nested/nested-lib@2.0", nested.getPurl());
        assertEquals("web/console.war/WEB-INF/lib/nested-lib-2.0.jar",
                nested.getEvidence().getOccurrences().get(0).getLocation(),
                "nested JAR occurrence should be relative to distribution root");

        Component html = findComponent(bom, Component.Type.FILE, "index.html");
        assertNotNull(html,
                "non-identifiable nested files should be preserved as FILE components");

        String warRef = war.getBomRef();
        var warDep = bom.getDependencies().stream()
                .filter(d -> warRef.equals(d.getRef())).findFirst().orElse(null);
        assertNotNull(warDep);
        assertTrue(warDep.getDependencies().stream()
                .anyMatch(d -> d.getRef().equals(nested.getBomRef())),
                "WAR should depend on nested-lib");
    }

    @Test
    void unpackedWarDetectedDespiteSharedJarAtTopLevel() throws Exception {
        // A jar exists both at lib/ (top-level) and inside an unpacked WAR
        // at web/app.war/WEB-INF/lib/. The shared hash must not prevent
        // computeUnpackPrefix from deriving "web/app.war/".
        Path sharedJar = createTestJar("shared-1.0.jar", "shared-content");
        Path warOnlyJar = createTestJar("war-only-1.0.jar", "war-only-content");
        Path htmlFile = createTestFile("index.html", "<html>war</html>");

        Path warFile = tempDir.resolve("app-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/shared-1.0.jar"));
            jos.write(Files.readAllBytes(sharedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("WEB-INF/lib/war-only-1.0.jar"));
            jos.write(Files.readAllBytes(warOnlyJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("index.html"));
            jos.write(Files.readAllBytes(htmlFile));
            jos.closeEntry();
        }

        Artifact sharedArtifact = createArtifact("org.example", "shared", "1.0",
                "jar", sharedJar.toFile());
        Artifact warArtifact = createArtifact("org.example", "app", "1.0",
                "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(sharedArtifact, warArtifact));

        MavenProject warProject = mock(MavenProject.class);
        when(warProject.getGroupId()).thenReturn("org.example");
        when(warProject.getArtifactId()).thenReturn("app");
        when(warProject.getVersion()).thenReturn("1.0");
        when(warProject.getPackaging()).thenReturn("war");

        Artifact warOnlyArtifact = createArtifact("org.example", "war-only", "1.0",
                "jar", warOnlyJar.toFile());
        when(warProject.getArtifacts()).thenReturn(
                Set.of(sharedArtifact, warOnlyArtifact));
        when(session.getProjects()).thenReturn(List.of(warProject));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("dist.zip").toFile());
        archiver.addFile(sharedJar.toFile(), "base/lib/shared-1.0.jar");
        archiver.addFile(sharedJar.toFile(),
                "base/web/app.war/WEB-INF/lib/shared-1.0.jar");
        archiver.addFile(warOnlyJar.toFile(),
                "base/web/app.war/WEB-INF/lib/war-only-1.0.jar");
        archiver.addFile(htmlFile.toFile(), "base/web/app.war/index.html");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        Component war = findComponent(bom, Component.Type.LIBRARY, "app");
        assertNotNull(war, "WAR should be detected as unpacked artifact");
        assertEquals("web/app.war/",
                war.getEvidence().getOccurrences().get(0).getLocation(),
                "WAR occurrence should be the unpack directory despite"
                        + " shared jar hash at top level");

        Component topShared = findComponent(bom, Component.Type.LIBRARY, "shared");
        assertNotNull(topShared, "shared jar should exist at top level");
        assertEquals("lib/shared-1.0.jar",
                topShared.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void unpackedArtifactNestedJarIdentifiedByPomProperties() throws Exception {
        Path nestedJar = createJarWithPomProperties("jolokia-json-2.4.jar",
                "org.jolokia", "jolokia-json", "2.4", "jolokia-content");

        Path warFile = tempDir.resolve("external-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/jolokia-json-2.4.jar"));
            jos.write(Files.readAllBytes(nestedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.ext", "external", "1.0",
                "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("out.zip").toFile());
        archiver.addFile(nestedJar.toFile(),
                "base/web/external/WEB-INF/lib/jolokia-json-2.4.jar");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        Component war = findComponent(bom, Component.Type.LIBRARY, "external");
        assertNotNull(war, "WAR should be detected as LIBRARY");
        assertEquals("web/external/",
                war.getEvidence().getOccurrences().get(0).getLocation(),
                "WAR occurrence should be the unpack location");

        assertNull(findComponent(bom, Component.Type.LIBRARY, "jolokia-json"),
                "nested JAR should NOT appear as top-level component");
        assertNotNull(war.getComponents(), "WAR should have nested components");
        assertEquals(1, war.getComponents().size());
        Component jolokia = war.getComponents().get(0);
        assertEquals("jolokia-json", jolokia.getName());
        assertEquals("pkg:maven/org.jolokia/jolokia-json@2.4", jolokia.getPurl());
        assertEquals("web/external/WEB-INF/lib/jolokia-json-2.4.jar",
                jolokia.getEvidence().getOccurrences().get(0).getLocation(),
                "nested JAR occurrence should be relative to distribution root");

        String warRef = war.getBomRef();
        var warDep = bom.getDependencies().stream()
                .filter(d -> warRef.equals(d.getRef())).findFirst().orElse(null);
        assertNotNull(warDep);
        assertTrue(warDep.getDependencies().stream()
                .anyMatch(d -> d.getRef().equals(jolokia.getBomRef())),
                "WAR should depend on jolokia-json");
    }

    @Test
    void shadedJarArtifactsNestedUnderFileComponent() throws Exception {
        // Shaded JAR with ambiguous filename — both artifactIds appear in it
        Path shadedJar = tempDir.resolve("ab-cd-1.0.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(shadedJar))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write("shaded-data".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/maven/com.example/ab/pom.properties"));
            jos.write("groupId=com.example\nartifactId=ab\nversion=1.0\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/maven/com.other/cd/pom.properties"));
            jos.write("groupId=com.other\nartifactId=cd\nversion=2.0\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }

        Path warFile = tempDir.resolve("mywar-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/ab-cd-1.0.jar"));
            jos.write(Files.readAllBytes(shadedJar));
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "mywar", "1.0",
                "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("out-shaded.zip").toFile());
        archiver.addFile(shadedJar.toFile(),
                "base/web/mywar/WEB-INF/lib/ab-cd-1.0.jar");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        Component war = findComponent(bom, Component.Type.LIBRARY, "mywar");
        assertNotNull(war, "WAR should be detected");

        Component file = findComponent(bom, Component.Type.FILE, "ab-cd-1.0.jar");
        assertNotNull(file, "shaded JAR should appear as FILE component");
        assertNotNull(file.getComponents(),
                "FILE component should have nested library components");
        assertEquals(2, file.getComponents().size());
        assertTrue(file.getComponents().stream()
                .anyMatch(c -> "ab".equals(c.getName()) && "1.0".equals(c.getVersion())));
        assertTrue(file.getComponents().stream()
                .anyMatch(c -> "cd".equals(c.getName()) && "2.0".equals(c.getVersion())));
    }

    @Test
    void virtualFilesReportsOutputPath() {
        assertEquals(List.of("bom.cdx.json"), handler.getVirtualFiles());
    }

    @Test
    void virtualFilesEmptyWhenOutputExternal() {
        handler.setOutputMode("external");
        assertEquals(List.of(), handler.getVirtualFiles());
    }

    @Test
    void externalOutputWritesBomNextToArchive() throws Exception {
        handler.setOutputMode("external");
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("app.properties", "data");

        Path archivePath = tempDir.resolve("myapp-1.0-dist.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(props.toFile(), "base/conf/app.properties");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("myapp-1.0-dist.zip.cdx.json");
        assertTrue(Files.exists(bomFile),
                "BOM should be written next to archive");
        String content = Files.readString(bomFile);
        assertTrue(content.contains("CycloneDX"));
        assertTrue(content.contains("SHA-256"),
                "external BOM should include archive hash");
    }

    @Test
    void outputAllWritesEmbeddedAndExternal() throws Exception {
        handler.setOutputMode("all");
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("both.properties", "data");

        Path archivePath = tempDir.resolve("both-test.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(props.toFile(), "base/conf/both.properties");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path externalBom = tempDir.resolve("both-test.zip.cdx.json");
        assertTrue(Files.exists(externalBom),
                "external BOM should be written next to archive");
        String externalContent = Files.readString(externalBom);
        assertTrue(externalContent.contains("CycloneDX"));

        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(archivePath.toFile())) {
            var bomEntry = zf.stream()
                    .filter(e -> e.getName().endsWith(".cdx.json"))
                    .findFirst().orElse(null);
            assertNotNull(bomEntry, "BOM should also be embedded in the archive");
        }
    }

    @Test
    void virtualFilesReportedWhenOutputAll() {
        handler.setOutputMode("all");
        assertEquals(List.of("bom.cdx.json"), handler.getVirtualFiles());
    }

    @Test
    void mainComponentPurlIncludesArchiveType() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        Path props = createTestFile("data.txt", "hello");

        ZipArchiver archiver = buildArchiver("base/data.txt", props);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component main = bom.getMetadata().getComponent();
        assertTrue(main.getPurl().contains("type=zip"),
                "main PURL should include archive type: " + main.getPurl());
    }

    @Test
    void invalidOutputThrows() throws Exception {
        handler.setOutputMode("none");
        Path props = createTestFile("data.txt", "hello");

        ZipArchiver archiver = buildArchiver("base/data.txt", props);
        var ex = assertThrows(ArchiverException.class,
                () -> handler.finalizeArchiveCreation(archiver));
        assertTrue(ex.getMessage().contains("none"));
    }

    @Test
    void unsupportedCycloneDxHashAlgorithmThrows() throws Exception {
        handler.setHashAlgorithm("SHA-224");
        Path props = createTestFile("data.txt", "hello");

        ZipArchiver archiver = buildArchiver("base/data.txt", props);
        var ex = assertThrows(ArchiverException.class,
                () -> handler.finalizeArchiveCreation(archiver));
        assertTrue(ex.getMessage().contains("CycloneDX"),
                "error should mention CycloneDX: " + ex.getMessage());
    }

    @Test
    void invalidFormatThrows() throws Exception {
        handler.setFormat("yaml");
        Path props = createTestFile("data.txt", "hello");

        ZipArchiver archiver = buildArchiver("base/data.txt", props);
        var ex = assertThrows(ArchiverException.class,
                () -> handler.finalizeArchiveCreation(archiver));
        assertTrue(ex.getMessage().contains("yaml"));
    }

    @Test
    void emptyArchiveProducesMinimalBom() throws Exception {
        handler.setOutputMode("external");
        when(project.getArtifacts()).thenReturn(Set.of());

        Path archivePath = tempDir.resolve("empty.zip");
        Path dummy = createTestFile("dummy.txt", "placeholder");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(dummy.toFile(), "base/dummy.txt");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("empty.zip.cdx.json");
        assertTrue(Files.exists(bomFile));
        String content = Files.readString(bomFile);
        assertTrue(content.contains("CycloneDX"));
        assertFalse(content.contains("\"type\" : \"library\""), "should have no library components");
    }

    @Test
    void licensesIncludedInBomComponents() throws Exception {
        Path jarFile = createTestJar("foo-1.0.jar", "hello");
        Artifact artifact = createArtifact("org.example", "foo", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        Model model = new Model();
        License license = new License();
        license.setName("The Apache Software License, Version 2.0");
        model.addLicense(license);
        when(effectiveModelResolver.resolveEffectiveModel("org.example", "foo", "1.0"))
                .thenReturn(model);

        ZipArchiver archiver = buildArchiver("base/lib/foo-1.0.jar", jarFile);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component lib = findComponent(bom, Component.Type.LIBRARY, "foo");
        assertNotNull(lib);
        assertNotNull(lib.getLicenseChoice(), "component should have license info");
        assertNotNull(lib.getLicenseChoice().getLicenses());
        assertFalse(lib.getLicenseChoice().getLicenses().isEmpty());
        assertEquals("Apache-2.0", lib.getLicenseChoice().getLicenses().get(0).getId());
    }

    @Test
    void failOnMissingLicenseThrowsException() throws Exception {
        handler.setFailOnMissingLicense(true);
        Path jarFile = createTestJar("foo-1.0.jar", "hello");
        Artifact artifact = createArtifact("org.example", "foo", "1.0", "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        Model projectModel = new Model();
        License projectLicense = new License();
        projectLicense.setName("Apache License, Version 2.0");
        projectModel.addLicense(projectLicense);
        when(effectiveModelResolver.resolveEffectiveModel("com.example", "test-app", "1.0"))
                .thenReturn(projectModel);

        Model artifactModel = new Model();
        when(effectiveModelResolver.resolveEffectiveModel("org.example", "foo", "1.0"))
                .thenReturn(artifactModel);

        ZipArchiver archiver = buildArchiver("base/lib/foo-1.0.jar", jarFile);
        var ex = assertThrows(ArchiverException.class,
                () -> handler.finalizeArchiveCreation(archiver));
        assertTrue(ex.getMessage().contains("org.example:foo:1.0"));
    }

    @Test
    void projectLicenseAppliedToMainComponent() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());

        Model projectModel = new Model();
        License projectLicense = new License();
        projectLicense.setName("Apache License, Version 2.0");
        projectModel.addLicense(projectLicense);
        when(effectiveModelResolver.resolveEffectiveModel("com.example", "test-app", "1.0"))
                .thenReturn(projectModel);

        handler.setOutputMode("external");
        Path archivePath = tempDir.resolve("main-lic.zip");
        Path dummy = createTestFile("dummy-lic.txt", "placeholder");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(dummy.toFile(), "base/dummy.txt");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("main-lic.zip.cdx.json");
        String json = Files.readString(bomFile);
        org.cyclonedx.parsers.JsonParser parser = new org.cyclonedx.parsers.JsonParser();
        Bom bom = parser.parse(json.getBytes(StandardCharsets.UTF_8));

        Component main = bom.getMetadata().getComponent();
        assertNotNull(main.getLicenseChoice(), "main component should have project license");
        assertEquals("Apache-2.0", main.getLicenseChoice().getLicenses().get(0).getId());
    }

    @Test
    void projectLicenseAppliedToFileComponents() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());

        Model projectModel = new Model();
        License projectLicense = new License();
        projectLicense.setName("MIT License");
        projectModel.addLicense(projectLicense);
        when(effectiveModelResolver.resolveEffectiveModel("com.example", "test-app", "1.0"))
                .thenReturn(projectModel);

        Path props = createTestFile("app.properties", "key=value");
        ZipArchiver archiver = buildArchiver("base/conf/app.properties", props);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        Component file = findComponent(bom, Component.Type.FILE, "app.properties");
        assertNotNull(file);
        assertNotNull(file.getLicenseChoice(), "file component should inherit project license");
        assertEquals("MIT", file.getLicenseChoice().getLicenses().get(0).getId());
    }

    @Test
    void externalSbomMatchedFileNotLostFromBom() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        lenient().when(project.getBasedir()).thenReturn(tempDir.toFile());

        Path npmFile = createTestFile("widget.js", "npm-pkg-data");
        String hash = SbomUtils.computeHash(
                MessageDigest.getInstance("SHA-256"), npmFile);

        Bom externalBom = new Bom();
        Component extComp = new Component();
        extComp.setType(Component.Type.LIBRARY);
        extComp.setGroup("@acme");
        extComp.setName("widget");
        extComp.setVersion("3.2.1");
        extComp.addHash(new Hash("SHA-256", hash));
        externalBom.addComponent(extComp);

        Path bomFile = tempDir.resolve("npm-sbom.cdx.json");
        BomWriter.writeJson(externalBom, bomFile, true);
        handler.setExternalSboms(bomFile.toString());

        ZipArchiver archiver = buildArchiver(
                "base/node_modules/@acme/widget/index.js", npmFile);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        assertNotNull(bom);

        // Step 1: external BOM must have been loaded and merged
        assertTrue(allComponentsRecursive(bom).stream()
                .anyMatch(c -> "widget".equals(c.getName())
                        && "@acme".equals(c.getGroup())),
                "precondition: external BOM components should be merged into output");

        // Step 2: hash matching must have removed the file from unmatched
        assertNull(findComponent(bom, Component.Type.FILE, "index.js"),
                "file whose hash matches external SBOM component"
                        + " should not appear as unmatched FILE");

        // Step 3: the file's archive path must still be traceable
        String expectedPath = "node_modules/@acme/widget/index.js";
        boolean pathTraceable = allComponentsRecursive(bom).stream()
                .anyMatch(c -> c.getEvidence() != null
                        && c.getEvidence().getOccurrences() != null
                        && c.getEvidence().getOccurrences().stream()
                                .anyMatch(o -> expectedPath.equals(
                                        o.getLocation())));
        assertTrue(pathTraceable,
                "file matched by external SBOM must have its archive path"
                        + " recorded as an occurrence on the matched component");
    }

    @Test
    void isSelectedFiltersSbomFilesInMergeMode() throws Exception {
        handler.setEmbeddedSboms("merge");
        FileInfo sbomFile = mock(FileInfo.class);
        when(sbomFile.getName()).thenReturn(
                "apache-artemis-1.0/web/console.war/META-INF/sbom/bom.cdx.json");
        assertFalse(handler.isSelected(sbomFile),
                "embedded SBOM file should be filtered in merge mode");
    }

    @Test
    void isSelectedAllowsSbomFilesInLinkMode() throws Exception {
        handler.setEmbeddedSboms("link");
        FileInfo sbomFile = mock(FileInfo.class);
        lenient().when(sbomFile.getName()).thenReturn(
                "apache-artemis-1.0/web/console.war/META-INF/sbom/bom.cdx.json");
        assertTrue(handler.isSelected(sbomFile),
                "embedded SBOM file should pass through in link mode");
    }

    @Test
    void isSelectedFiltersSbomDirectoryInMergeMode() throws Exception {
        handler.setEmbeddedSboms("merge");
        FileInfo sbomDir = mock(FileInfo.class);
        when(sbomDir.getName()).thenReturn(
                "apache-artemis-1.0/web/console.war/META-INF/sbom/");
        assertFalse(handler.isSelected(sbomDir),
                "embedded SBOM directory should be filtered in merge mode");
    }

    @Test
    void isSelectedPassesNonSbomFiles() throws Exception {
        handler.setEmbeddedSboms("merge");
        FileInfo regularFile = mock(FileInfo.class);
        when(regularFile.getName()).thenReturn("base/lib/guava-33.0.jar");
        assertTrue(handler.isSelected(regularFile),
                "regular files should pass through");
    }

    @Test
    void externalSbomComponentFilteredWhenOccurrenceNotInArchive() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        lenient().when(project.getBasedir()).thenReturn(tempDir.toFile());

        // Archive contains a file that does NOT match the external component
        Path otherFile = createTestFile("other.txt", "other-data");

        // External SBOM claims a component at a path not present in the archive,
        // with a hash that doesn't match any archive file
        Bom externalBom = new Bom();
        Component extComp = new Component();
        extComp.setType(Component.Type.LIBRARY);
        extComp.setGroup("com.google.guava");
        extComp.setName("failureaccess");
        extComp.setVersion("1.0");
        extComp.setPurl("pkg:maven/com.google.guava/failureaccess@1.0");
        extComp.setBomRef("pkg:maven/com.google.guava/failureaccess@1.0");
        extComp.addHash(new Hash("SHA-256",
                "0000000000000000000000000000000000000000000000000000000000000000"));
        org.cyclonedx.model.Evidence evidence = new org.cyclonedx.model.Evidence();
        org.cyclonedx.model.component.evidence.Occurrence occ = new org.cyclonedx.model.component.evidence.Occurrence();
        occ.setLocation("WEB-INF/lib/failureaccess-1.0.jar");
        evidence.addOccurrence(occ);
        extComp.setEvidence(evidence);
        externalBom.addComponent(extComp);

        Path bomFile = tempDir.resolve("ext.cdx.json");
        BomWriter.writeJson(externalBom, bomFile, true);
        handler.setExternalSboms(bomFile.toString());

        ZipArchiver archiver = buildArchiver("base/conf/other.txt", otherFile);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        assertNotNull(bom);

        assertFalse(allComponentsRecursive(bom).stream()
                .anyMatch(c -> "failureaccess".equals(c.getName())
                        && "com.google.guava".equals(c.getGroup())),
                "component with non-matching occurrence path should be filtered out");
    }

    @Test
    void npmComponentWithSourceOccurrenceSurvivesFiltering() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        lenient().when(project.getBasedir()).thenReturn(tempDir.toFile());

        Path jsFile = createTestFile("main.js", "bundled-code");

        // npm component with source-code occurrence (from cdxgen) and SHA-512
        // hash — neither matches archive content, but npm components should
        // not be rejected based on source-path occurrences
        Bom externalBom = new Bom();
        Component react = new Component();
        react.setType(Component.Type.FRAMEWORK);
        react.setName("react");
        react.setVersion("18.3.1");
        react.setPurl("pkg:npm/react@18.3.1");
        react.setBomRef("pkg:npm/react@18.3.1");
        react.addHash(new Hash("SHA-512", "abc123"));
        org.cyclonedx.model.Evidence evidence = new org.cyclonedx.model.Evidence();
        org.cyclonedx.model.component.evidence.Occurrence occ = new org.cyclonedx.model.component.evidence.Occurrence();
        occ.setLocation("packages/my-plugin/src/App.tsx");
        evidence.addOccurrence(occ);
        react.setEvidence(evidence);
        externalBom.addComponent(react);

        Path bomFile = tempDir.resolve("npm.cdx.json");
        BomWriter.writeJson(externalBom, bomFile, true);
        handler.setExternalSboms(bomFile.toString());

        ZipArchiver archiver = buildArchiver("base/static/js/main.js", jsFile);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        assertNotNull(bom);

        assertTrue(allComponentsRecursive(bom).stream()
                .anyMatch(c -> "react".equals(c.getName())),
                "npm component with non-matching source-code occurrence"
                        + " should survive filtering");
    }

    @Test
    void duplicateBomRefsAreDeduplicatedAcrossNestingLevels() throws Exception {
        // Same shaded dep (jcip-annotations) bundled in two different JARs
        // at different archive locations — bom-refs must be unique
        Path shadedJar1 = tempDir.resolve("nimbus-10.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(shadedJar1))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write("nimbus10-content".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry(
                    "META-INF/maven/com.nimbusds/nimbus/pom.properties"));
            jos.write("groupId=com.nimbusds\nartifactId=nimbus\nversion=10\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry(
                    "META-INF/maven/org.x/jcip/pom.properties"));
            jos.write("groupId=org.x\nartifactId=jcip\nversion=1.0\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }

        Path shadedJar2 = tempDir.resolve("nimbus-11.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(shadedJar2))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write("nimbus11-content".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry(
                    "META-INF/maven/com.nimbusds/nimbus/pom.properties"));
            jos.write("groupId=com.nimbusds\nartifactId=nimbus\nversion=11\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry(
                    "META-INF/maven/org.x/jcip/pom.properties"));
            jos.write("groupId=org.x\nartifactId=jcip\nversion=1.0\n"
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }

        when(project.getArtifacts()).thenReturn(Set.of());

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("out-dedup.zip").toFile());
        archiver.addFile(shadedJar1.toFile(), "base/lib/nimbus-10.jar");
        archiver.addFile(shadedJar2.toFile(), "base/lib/nimbus-11.jar");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        // Collect all bom-refs recursively
        List<String> allRefs = new java.util.ArrayList<>();
        java.util.function.Consumer<List<Component>> collectRefs = new java.util.function.Consumer<>() {
            @Override
            public void accept(List<Component> comps) {
                for (Component c : comps) {
                    if (c.getBomRef() != null) {
                        allRefs.add(c.getBomRef());
                    }
                    if (c.getComponents() != null) {
                        accept(c.getComponents());
                    }
                }
            }
        };
        if (bom.getComponents() != null) {
            collectRefs.accept(bom.getComponents());
        }

        Set<String> unique = new java.util.HashSet<>(allRefs);
        assertEquals(allRefs.size(), unique.size(),
                "all bom-refs must be unique, but found duplicates: "
                        + allRefs.stream()
                                .filter(r -> java.util.Collections.frequency(allRefs, r) > 1)
                                .distinct().toList());

        // Every component bom-ref must have a matching dependency entry
        Set<String> depRefs = new java.util.HashSet<>();
        if (bom.getDependencies() != null) {
            for (org.cyclonedx.model.Dependency dep : bom.getDependencies()) {
                depRefs.add(dep.getRef());
            }
        }
        for (String ref : allRefs) {
            assertTrue(depRefs.contains(ref),
                    "component bom-ref '" + ref
                            + "' must have a matching dependency entry");
        }

        // Renamed (#2) dependency entries must carry the same dependsOn
        // children as the original
        if (bom.getDependencies() != null) {
            for (org.cyclonedx.model.Dependency dep : bom.getDependencies()) {
                String ref = dep.getRef();
                int hashIdx = ref.indexOf('#');
                if (hashIdx > 0) {
                    String originalRef = ref.substring(0, hashIdx);
                    org.cyclonedx.model.Dependency originalDep = bom.getDependencies().stream()
                            .filter(d -> originalRef.equals(d.getRef()))
                            .findFirst().orElse(null);
                    assertNotNull(originalDep,
                            "original dep for " + ref + " must exist");
                    int cloneSize = dep.getDependencies() == null
                            ? 0
                            : dep.getDependencies().size();
                    int origSize = originalDep.getDependencies() == null
                            ? 0
                            : originalDep.getDependencies().size();
                    assertEquals(origSize, cloneSize,
                            "cloned dep " + ref
                                    + " must have same dependsOn count as "
                                    + originalRef);
                }
            }
        }
    }

    @Test
    void fileComponentReplacedByLibraryWithMatchingHash() {
        String hash = "ca70c90a5d1ce1511880ce9c93d4ad22108f61111d3daf91eb52762b571bd179";

        Bom bom = new Bom();
        org.cyclonedx.model.Metadata meta = new org.cyclonedx.model.Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef("pkg:maven/com.example/app@1.0");
        meta.setComponent(main);
        bom.setMetadata(meta);

        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("caffeine-3.2.3.jar");
        fileComp.setBomRef("file:lib/caffeine-3.2.3.jar");
        fileComp.setPurl("pkg:generic/caffeine-3.2.3.jar?checksum=sha256:" + hash);
        fileComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component libComp = new Component();
        libComp.setType(Component.Type.LIBRARY);
        libComp.setGroup("com.github.ben-manes.caffeine");
        libComp.setName("caffeine");
        libComp.setVersion("3.2.3");
        libComp.setBomRef("pkg:maven/com.github.ben-manes.caffeine/caffeine@3.2.3");
        libComp.setPurl("pkg:maven/com.github.ben-manes.caffeine/caffeine@3.2.3");
        libComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        bom.setComponents(new java.util.ArrayList<>(List.of(fileComp, libComp)));

        org.cyclonedx.model.Dependency mainDep = new org.cyclonedx.model.Dependency(main.getBomRef());
        mainDep.addDependency(new org.cyclonedx.model.Dependency(
                fileComp.getBomRef()));
        bom.addDependency(mainDep);
        bom.addDependency(new org.cyclonedx.model.Dependency(
                fileComp.getBomRef()));
        org.cyclonedx.model.Dependency libDep = new org.cyclonedx.model.Dependency(libComp.getBomRef());
        libDep.addDependency(new org.cyclonedx.model.Dependency(
                "pkg:maven/org.jspecify/jspecify@1.0.0"));
        bom.addDependency(libDep);

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size());
        assertEquals("caffeine", bom.getComponents().get(0).getName());
        assertEquals(Component.Type.LIBRARY, bom.getComponents().get(0).getType());

        assertFalse(bom.getDependencies().stream()
                .anyMatch(d -> "file:lib/caffeine-3.2.3.jar".equals(d.getRef())),
                "file dependency entry should be removed");

        org.cyclonedx.model.Dependency rootDep = bom.getDependencies().stream()
                .filter(d -> main.getBomRef().equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(rootDep);
        assertNotNull(rootDep.getDependencies());
        assertTrue(rootDep.getDependencies().stream()
                .anyMatch(d -> libComp.getBomRef().equals(d.getRef())),
                "root should now depend on library ref");
        assertFalse(rootDep.getDependencies().stream()
                .anyMatch(d -> d.getRef().startsWith("file:")),
                "root should not have file ref in dependsOn");

        assertTrue(bom.getDependencies().stream()
                .anyMatch(d -> libComp.getBomRef().equals(d.getRef())),
                "library dependency entry should be preserved");
    }

    @Test
    void multipleFileComponentsWithSameHashAllReplaced() {
        String hash = "ab12cd34ef56789000000000000000000000000000000000000000000000abcd";

        Bom bom = new Bom();
        org.cyclonedx.model.Metadata meta = new org.cyclonedx.model.Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef("pkg:maven/com.example/app@1.0");
        meta.setComponent(main);
        bom.setMetadata(meta);

        Component fileComp1 = new Component();
        fileComp1.setType(Component.Type.FILE);
        fileComp1.setName("guava-33.0.jar");
        fileComp1.setBomRef("file:lib/guava-33.0.jar");
        fileComp1.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component fileComp2 = new Component();
        fileComp2.setType(Component.Type.FILE);
        fileComp2.setName("guava-33.0.jar");
        fileComp2.setBomRef("file:modules/guava-33.0.jar");
        fileComp2.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        Component libComp = new Component();
        libComp.setType(Component.Type.LIBRARY);
        libComp.setGroup("com.google.guava");
        libComp.setName("guava");
        libComp.setVersion("33.0");
        libComp.setBomRef("pkg:maven/com.google.guava/guava@33.0");
        libComp.addHash(new Hash(Hash.Algorithm.SHA_256, hash));

        bom.setComponents(new java.util.ArrayList<>(
                List.of(fileComp1, fileComp2, libComp)));

        org.cyclonedx.model.Dependency mainDep = new org.cyclonedx.model.Dependency(main.getBomRef());
        mainDep.addDependency(new org.cyclonedx.model.Dependency(
                fileComp1.getBomRef()));
        mainDep.addDependency(new org.cyclonedx.model.Dependency(
                fileComp2.getBomRef()));
        bom.addDependency(mainDep);
        bom.addDependency(new org.cyclonedx.model.Dependency(
                fileComp1.getBomRef()));
        bom.addDependency(new org.cyclonedx.model.Dependency(
                fileComp2.getBomRef()));
        bom.addDependency(new org.cyclonedx.model.Dependency(
                libComp.getBomRef()));

        SbomGenerator.replaceFileComponentsWithLibraries(bom, "sha256");

        assertEquals(1, bom.getComponents().size(),
                "only the library component should remain");
        assertEquals("guava", bom.getComponents().get(0).getName());

        assertFalse(bom.getDependencies().stream()
                .anyMatch(d -> d.getRef().startsWith("file:")),
                "no file dependency entries should remain");

        org.cyclonedx.model.Dependency rootDep = bom.getDependencies().stream()
                .filter(d -> main.getBomRef().equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(rootDep);
        assertTrue(rootDep.getDependencies().stream()
                .anyMatch(d -> libComp.getBomRef().equals(d.getRef())),
                "root should depend on library ref");
        assertFalse(rootDep.getDependencies().stream()
                .anyMatch(d -> d.getRef().startsWith("file:")),
                "root should not have any file refs in dependsOn");
    }

    @Test
    void collectArchiveEntriesSkipsSbomFilesInMergeMode() throws Exception {
        when(project.getArtifacts()).thenReturn(Set.of());
        handler.setOutputMode("external");

        Path dataFile = createTestFile("app-data.txt", "data");
        Path sbomFile = createTestFile("embedded.cdx.json", "{\"bomFormat\":\"CycloneDX\"}");

        Path archivePath = tempDir.resolve("test-skip.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(dataFile.toFile(), "base/data.txt");
        archiver.addFile(sbomFile.toFile(), "base/web/app.war/META-INF/sbom/bom.cdx.json");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path extBom = tempDir.resolve("test-skip.zip.cdx.json");
        assertTrue(Files.exists(extBom));
        Bom bom = BomReader.readBom(extBom.toFile());
        assertNotNull(bom);

        assertNull(findComponent(bom, Component.Type.FILE, "bom.cdx.json"),
                "embedded SBOM file should not appear as FILE component");
        assertNotNull(findComponent(bom, Component.Type.FILE, "data.txt"),
                "regular file should appear as FILE component");
    }

    private static List<Component> allComponentsRecursive(Bom bom) {
        List<Component> result = new java.util.ArrayList<>();
        if (bom.getComponents() != null) {
            collectComponents(bom.getComponents(), result);
        }
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null
                && bom.getMetadata().getComponent().getComponents() != null) {
            collectComponents(bom.getMetadata().getComponent().getComponents(), result);
        }
        return result;
    }

    private static void collectComponents(List<Component> components,
            List<Component> result) {
        for (Component c : components) {
            result.add(c);
            if (c.getComponents() != null) {
                collectComponents(c.getComponents(), result);
            }
        }
    }

    @Test
    void sameJarNestedInTwoWarsPreservedInBoth() throws Exception {
        Path sharedJar = createTestJar("common-1.0.jar", "common-content");

        Path alphaPage = createTestFile("alpha.html", "<html>alpha</html>");
        Path war1 = tempDir.resolve("alpha-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(war1))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/common-1.0.jar"));
            jos.write(Files.readAllBytes(sharedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("index.html"));
            jos.write(Files.readAllBytes(alphaPage));
            jos.closeEntry();
        }
        Path betaPage = createTestFile("beta.html", "<html>beta</html>");
        Path war2 = tempDir.resolve("beta-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(war2))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/common-1.0.jar"));
            jos.write(Files.readAllBytes(sharedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("index.html"));
            jos.write(Files.readAllBytes(betaPage));
            jos.closeEntry();
        }

        Artifact sharedArtifact = createArtifact("org.example", "common", "1.0",
                "jar", sharedJar.toFile());
        Artifact war1Artifact = createArtifact("org.example", "alpha", "1.0",
                "war", war1.toFile());
        Artifact war2Artifact = createArtifact("org.example", "beta", "1.0",
                "war", war2.toFile());
        when(project.getArtifacts()).thenReturn(
                Set.of(sharedArtifact, war1Artifact, war2Artifact));

        MavenProject alphaProject = mock(MavenProject.class);
        when(alphaProject.getGroupId()).thenReturn("org.example");
        when(alphaProject.getArtifactId()).thenReturn("alpha");
        when(alphaProject.getVersion()).thenReturn("1.0");
        when(alphaProject.getPackaging()).thenReturn("war");
        when(alphaProject.getArtifacts()).thenReturn(Set.of(sharedArtifact));

        MavenProject betaProject = mock(MavenProject.class);
        when(betaProject.getGroupId()).thenReturn("org.example");
        when(betaProject.getArtifactId()).thenReturn("beta");
        when(betaProject.getVersion()).thenReturn("1.0");
        when(betaProject.getPackaging()).thenReturn("war");
        when(betaProject.getArtifacts()).thenReturn(Set.of(sharedArtifact));

        when(session.getProjects()).thenReturn(List.of(alphaProject, betaProject));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("dist.zip").toFile());
        archiver.addFile(sharedJar.toFile(),
                "base/web/alpha.war/WEB-INF/lib/common-1.0.jar");
        archiver.addFile(alphaPage.toFile(), "base/web/alpha.war/index.html");
        archiver.addFile(sharedJar.toFile(),
                "base/web/beta.war/WEB-INF/lib/common-1.0.jar");
        archiver.addFile(betaPage.toFile(), "base/web/beta.war/index.html");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        Component alpha = findComponent(bom, Component.Type.LIBRARY, "alpha");
        Component beta = findComponent(bom, Component.Type.LIBRARY, "beta");
        assertNotNull(alpha, "alpha WAR should be detected");
        assertNotNull(beta, "beta WAR should be detected");

        assertNotNull(alpha.getComponents(), "alpha should have nested components");
        assertEquals(1, alpha.getComponents().size(),
                "common JAR should be nested under alpha");
        assertEquals("common", alpha.getComponents().get(0).getName());

        assertNotNull(beta.getComponents(), "beta should have nested components");
        assertEquals(1, beta.getComponents().size(),
                "common JAR should be nested under beta");
        assertEquals("common", beta.getComponents().get(0).getName());

        assertNull(findComponent(bom, Component.Type.LIBRARY, "common"),
                "common should NOT appear as a top-level component");
    }

    @Test
    void ignoredEmbeddedSbomPreservedAsUnmatchedFile() throws Exception {
        handler.setEmbeddedSboms("ignore");
        handler.setOutputMode("external");
        when(project.getArtifacts()).thenReturn(Set.of());

        Path sbomFile = createTestFile("bom.cdx.json",
                "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\","
                        + "\"components\":[]}");

        Path archivePath = tempDir.resolve("ignore-test.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(sbomFile.toFile(), "base/META-INF/sbom/bom.cdx.json");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("ignore-test.zip.cdx.json");
        assertTrue(Files.exists(bomFile), "external BOM should be written");
        String json = Files.readString(bomFile);
        org.cyclonedx.parsers.JsonParser parser = new org.cyclonedx.parsers.JsonParser();
        Bom bom = parser.parse(json.getBytes(StandardCharsets.UTF_8));

        Component file = findComponent(bom, Component.Type.FILE, "bom.cdx.json");
        assertNotNull(file,
                "SBOM file should remain as unmatched FILE component"
                        + " when embeddedSbomHandling=ignore");
        assertEquals("META-INF/sbom/bom.cdx.json",
                file.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void embeddedSbomFromArtifactNotInArchiveIsIgnored() throws Exception {
        Path includedJar = createTestJar("lib-1.0.jar", "included-content");
        Artifact includedArtifact = createArtifact("org.example", "lib", "1.0",
                "jar", includedJar.toFile());

        Path testJar = createJarWithEmbeddedSbom("test-utils-1.0.jar",
                "test-sbom-data", "org.test", "test-helper", "1.0");
        Artifact testArtifact = createArtifact("org.example", "test-utils",
                "1.0", "jar", "test", testJar.toFile());

        Path excludedCompileJar = createJarWithEmbeddedSbom(
                "optional-lib-2.0.jar", "optional-data",
                "org.optional", "optional-dep", "2.0");
        Artifact excludedCompileArtifact = createArtifact("org.example",
                "optional-lib", "2.0", "jar", excludedCompileJar.toFile());

        when(project.getArtifacts()).thenReturn(
                Set.of(includedArtifact, testArtifact, excludedCompileArtifact));

        ZipArchiver archiver = buildArchiver(
                "base/lib/lib-1.0.jar", includedJar);
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);
        assertNotNull(bom);

        List<String> leakedNames = allComponentsRecursive(bom).stream()
                .map(Component::getName)
                .filter(n -> "test-helper".equals(n) || "optional-dep".equals(n))
                .toList();
        assertTrue(leakedNames.isEmpty(),
                "SBOMs from dependencies not in the archive should not"
                        + " appear in the output BOM regardless of scope,"
                        + " but found: " + leakedNames);
    }

    @Test
    void unpackedWarEmbeddedSbomComponentsSurviveFiltering() throws Exception {
        // Models the real pipeline: an embedded SBOM inside an unpacked WAR
        // has flat top-level components — the upstream WAR component (with
        // empty occurrence meaning "the root"), npm components (no hashes,
        // no occurrences), a file component with a file: bom-ref, and a
        // Maven library matched by occurrence path. All must survive
        // filterSbomByArchive and get merged under the unpacked WAR.
        Path nestedJar = createTestJar("hawtio-1.0.jar", "hawtio-content");
        Path jsFile = createTestFile("main.js", "console.log('hello')");

        Bom embeddedBom = new Bom();

        // Upstream WAR component with empty occurrence (represents "the root")
        Component upstreamWar = new Component();
        upstreamWar.setType(Component.Type.LIBRARY);
        upstreamWar.setGroup("org.upstream");
        upstreamWar.setName("upstream-war");
        upstreamWar.setVersion("1.0");
        upstreamWar.setPurl("pkg:maven/org.upstream/upstream-war@1.0?type=war");
        upstreamWar.setBomRef("pkg:maven/org.upstream/upstream-war@1.0?type=war");
        org.cyclonedx.model.Evidence warEvidence = new org.cyclonedx.model.Evidence();
        org.cyclonedx.model.component.evidence.Occurrence warOcc = new org.cyclonedx.model.component.evidence.Occurrence();
        warOcc.setLocation("");
        warEvidence.addOccurrence(warOcc);
        upstreamWar.setEvidence(warEvidence);
        embeddedBom.addComponent(upstreamWar);

        // Flat npm components (no hashes, no occurrences — pass via can't-verify)
        Component react = new Component();
        react.setType(Component.Type.LIBRARY);
        react.setName("react");
        react.setVersion("18.0.0");
        react.setPurl("pkg:npm/react@18.0.0");
        react.setBomRef("pkg:npm/react@18.0.0");
        embeddedBom.addComponent(react);

        Component reactDom = new Component();
        reactDom.setType(Component.Type.LIBRARY);
        reactDom.setName("react-dom");
        reactDom.setVersion("18.0.0");
        reactDom.setPurl("pkg:npm/react-dom@18.0.0");
        reactDom.setBomRef("pkg:npm/react-dom@18.0.0");
        embeddedBom.addComponent(reactDom);

        // File component with a file: bom-ref (tests prefixFileBomRef)
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("app.js");
        fileComp.setBomRef("file:static/js/app.js");
        embeddedBom.addComponent(fileComp);

        // Maven library matched by occurrence path
        Component mavenLib = new Component();
        mavenLib.setType(Component.Type.LIBRARY);
        mavenLib.setGroup("io.hawt");
        mavenLib.setName("hawtio");
        mavenLib.setVersion("1.0");
        mavenLib.setPurl("pkg:maven/io.hawt/hawtio@1.0");
        mavenLib.setBomRef("pkg:maven/io.hawt/hawtio@1.0");
        org.cyclonedx.model.Evidence libEvidence = new org.cyclonedx.model.Evidence();
        org.cyclonedx.model.component.evidence.Occurrence libOcc = new org.cyclonedx.model.component.evidence.Occurrence();
        libOcc.setLocation("WEB-INF/lib/hawtio-1.0.jar");
        libEvidence.addOccurrence(libOcc);
        mavenLib.setEvidence(libEvidence);
        String hawtioHash = SbomUtils.computeHash(
                MessageDigest.getInstance("SHA-256"), nestedJar);
        mavenLib.addHash(new Hash(Hash.Algorithm.SHA_256, hawtioHash));
        embeddedBom.addComponent(mavenLib);

        // Dependency entries for npm components
        org.cyclonedx.model.Dependency reactDomDep = new org.cyclonedx.model.Dependency("pkg:npm/react-dom@18.0.0");
        reactDomDep.addDependency(
                new org.cyclonedx.model.Dependency("pkg:npm/react@18.0.0"));
        embeddedBom.addDependency(reactDomDep);
        embeddedBom.addDependency(
                new org.cyclonedx.model.Dependency("pkg:npm/react@18.0.0"));
        embeddedBom.addDependency(
                new org.cyclonedx.model.Dependency("file:static/js/app.js"));

        // Create the WAR file with the embedded SBOM
        Path bomJson = tempDir.resolve("embedded-bom.cdx.json");
        BomWriter.writeJson(embeddedBom, bomJson, false);
        byte[] bomBytes = Files.readAllBytes(bomJson);

        Path warFile = tempDir.resolve("overlay-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/hawtio-1.0.jar"));
            jos.write(Files.readAllBytes(nestedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("static/js/main.js"));
            jos.write(Files.readAllBytes(jsFile));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/sbom/bom.cdx.json"));
            jos.write(bomBytes);
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "overlay", "1.0",
                "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        MavenProject overlayProject = mock(MavenProject.class);
        when(overlayProject.getGroupId()).thenReturn("org.example");
        when(overlayProject.getArtifactId()).thenReturn("overlay");
        when(overlayProject.getVersion()).thenReturn("1.0");
        when(overlayProject.getPackaging()).thenReturn("war");

        Artifact hawtioArtifact = createArtifact("io.hawt", "hawtio", "1.0",
                "jar", nestedJar.toFile());
        when(overlayProject.getArtifacts()).thenReturn(Set.of(hawtioArtifact));
        when(session.getProjects()).thenReturn(List.of(overlayProject));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("dist.zip").toFile());
        archiver.addFile(nestedJar.toFile(),
                "base/web/app.war/WEB-INF/lib/hawtio-1.0.jar");
        archiver.addFile(jsFile.toFile(),
                "base/web/app.war/static/js/main.js");
        handler.finalizeArchiveCreation(archiver);

        Bom bom = readBomFromArchiver(archiver);

        Component war = findComponent(bom, Component.Type.LIBRARY, "overlay");
        assertNotNull(war, "unpacked WAR should be detected as LIBRARY");
        assertNotNull(war.getComponents(), "WAR should have nested components");

        // Empty-occurrence component survives filterSbomByArchive
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> "upstream-war".equals(c.getName())),
                "component with empty occurrence should survive filtering");

        // Flat npm components (no hashes) survive via can't-verify path
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())),
                "npm component without hashes should survive filtering");
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> "react-dom".equals(c.getName())),
                "npm component without hashes should survive filtering");

        // Maven library matched by occurrence survives
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> "hawtio".equals(c.getName())),
                "Maven library matched by occurrence should survive filtering");

        // npm dependency entries survive (not pruned by filterSbomByArchive)
        var reactDomDepEntry = bom.getDependencies().stream()
                .filter(d -> d.getRef().equals("pkg:npm/react-dom@18.0.0"))
                .findFirst().orElse(null);
        assertNotNull(reactDomDepEntry,
                "dependency entry for npm component should be imported");
        assertTrue(reactDomDepEntry.getDependencies().stream()
                .anyMatch(d -> d.getRef().equals("pkg:npm/react@18.0.0")),
                "react-dom should depend on react");

        // file: bom-ref prefixed consistently with dependency entry ref
        String expectedFileRef = "file:web/app.war/static/js/app.js";
        assertTrue(war.getComponents().stream()
                .anyMatch(c -> expectedFileRef.equals(c.getBomRef())),
                "file: bom-ref should be prefixed with parent path");
        assertNotNull(bom.getDependencies().stream()
                .filter(d -> d.getRef().equals(expectedFileRef))
                .findFirst().orElse(null),
                "dependency entry ref should match prefixed bom-ref");
    }

    @Test
    void embeddedSbomFromArtifactJarDetectedAndMergedUnderParent() throws Exception {
        handler.setOutputMode("external");

        Path innerJar = createJarWithEmbeddedSbom("console-1.0.jar",
                "console-content", "org.frontend", "react-app", "1.0");
        Artifact consoleArtifact = createArtifact("org.example", "console", "1.0",
                "jar", innerJar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(consoleArtifact));

        Path archivePath = tempDir.resolve("dist-embedded.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        archiver.addFile(innerJar.toFile(), "base/lib/console-1.0.jar");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("dist-embedded.zip.cdx.json");
        assertTrue(Files.exists(bomFile));
        Bom bom = BomReader.readBom(bomFile.toFile());
        assertNotNull(bom);

        Component console = findComponent(bom, Component.Type.LIBRARY, "console");
        assertNotNull(console, "JAR should be detected as LIBRARY component");
        assertNotNull(console.getComponents(),
                "embedded SBOM components should be nested under parent JAR");
        assertTrue(console.getComponents().stream()
                .anyMatch(c -> "react-app".equals(c.getName())),
                "embedded SBOM library should appear as nested component");

        assertNull(findComponent(bom, Component.Type.FILE, "bom.cdx.json"),
                "SBOM file itself should NOT appear as FILE component");
    }

    @Test
    void multiLevelEmbeddedSbomNesting() throws Exception {
        // Tests 2-level nesting via unpacked WAR:
        // distribution → console (unpacked WAR) → inner-war → lodash (npm)
        handler.setOutputMode("external");

        Path nestedJar = createTestJar("hawtio-1.0.jar", "hawtio-content");

        Bom embeddedBom = new Bom();

        Component upstreamWar = new Component();
        upstreamWar.setType(Component.Type.LIBRARY);
        upstreamWar.setGroup("org.upstream");
        upstreamWar.setName("inner-war");
        upstreamWar.setVersion("1.0");
        upstreamWar.setPurl("pkg:maven/org.upstream/inner-war@1.0?type=war");
        upstreamWar.setBomRef("pkg:maven/org.upstream/inner-war@1.0?type=war");
        org.cyclonedx.model.Evidence warEvidence = new org.cyclonedx.model.Evidence();
        org.cyclonedx.model.component.evidence.Occurrence warOcc = new org.cyclonedx.model.component.evidence.Occurrence();
        warOcc.setLocation("");
        warEvidence.addOccurrence(warOcc);
        upstreamWar.setEvidence(warEvidence);

        Component npmComp = new Component();
        npmComp.setType(Component.Type.LIBRARY);
        npmComp.setName("lodash");
        npmComp.setVersion("4.17.21");
        npmComp.setPurl("pkg:npm/lodash@4.17.21");
        npmComp.setBomRef("pkg:npm/lodash@4.17.21");
        upstreamWar.addComponent(npmComp);

        embeddedBom.addComponent(upstreamWar);

        Path bomJson = tempDir.resolve("multi-level-embedded.cdx.json");
        BomWriter.writeJson(embeddedBom, bomJson, false);
        byte[] bomBytes = Files.readAllBytes(bomJson);

        Path warFile = tempDir.resolve("console-1.0.war");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(warFile))) {
            jos.putNextEntry(new JarEntry("WEB-INF/lib/hawtio-1.0.jar"));
            jos.write(Files.readAllBytes(nestedJar));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/sbom/bom.cdx.json"));
            jos.write(bomBytes);
            jos.closeEntry();
        }

        Artifact warArtifact = createArtifact("org.example", "console", "1.0",
                "war", warFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(warArtifact));

        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("dist-multilevel.zip").toFile());
        archiver.addFile(nestedJar.toFile(),
                "base/web/console.war/WEB-INF/lib/hawtio-1.0.jar");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("dist-multilevel.zip.cdx.json");
        assertTrue(Files.exists(bomFile));
        Bom bom = BomReader.readBom(bomFile.toFile());
        assertNotNull(bom);

        Component console = findComponent(bom, Component.Type.LIBRARY, "console");
        assertNotNull(console, "unpacked WAR should be detected as LIBRARY component");
        assertNotNull(console.getComponents(),
                "embedded SBOM components should be nested under WAR");

        Component innerWarComp = console.getComponents().stream()
                .filter(c -> "inner-war".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(innerWarComp, "inner-war should be nested under console");

        assertNotNull(innerWarComp.getComponents(),
                "inner-war should have its own nested components");
        assertTrue(innerWarComp.getComponents().stream()
                .anyMatch(c -> "lodash".equals(c.getName())),
                "lodash should be nested under inner-war (2-level nesting)");
    }

    @Test
    void attachWithEmbeddedOutputModeThrows() throws Exception {
        handler.setAttach(true);
        handler.setOutputMode("embedded");
        Path props = createTestFile("data.txt", "hello");

        ZipArchiver archiver = buildArchiver("base/data.txt", props);
        var ex = assertThrows(ArchiverException.class,
                () -> handler.finalizeArchiveCreation(archiver));
        assertTrue(ex.getMessage().contains("outputMode"),
                "error should mention outputMode: " + ex.getMessage());
    }

    @Test
    void attachWithExternalOutputCallsProjectHelper() throws Exception {
        handler.setAttach(true);
        handler.setOutputMode("external");
        when(project.getArtifacts()).thenReturn(Set.of());

        Path archivePath = tempDir.resolve("attach-test.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        Path props = createTestFile("attach-data.txt", "data");
        archiver.addFile(props.toFile(), "base/conf/app.properties");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("attach-test.zip.cdx.json");
        assertTrue(Files.exists(bomFile), "external BOM should be written");
        verify(projectHelper).attachArtifact(
                eq(project), eq("cdx.json"), isNull(), eq(bomFile.toFile()));
    }

    @Test
    void attachWithXmlFormatUsesCorrectType() throws Exception {
        handler.setAttach(true);
        handler.setOutputMode("external");
        handler.setFormat("xml");
        when(project.getArtifacts()).thenReturn(Set.of());

        Path archivePath = tempDir.resolve("attach-xml.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        Path props = createTestFile("xml-data.txt", "data");
        archiver.addFile(props.toFile(), "base/data.txt");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        verify(projectHelper).attachArtifact(
                eq(project), eq("cdx.xml"), isNull(), any(File.class));
    }

    @Test
    void attachSkippedWhenAssemblyPluginAttachIsFalse() throws Exception {
        handler.setAttach(true);
        handler.setOutputMode("external");
        when(project.getArtifacts()).thenReturn(Set.of());

        // Configure assembly plugin with attach=false
        Plugin assemblyPlugin = new Plugin();
        assemblyPlugin.setGroupId("org.apache.maven.plugins");
        assemblyPlugin.setArtifactId("maven-assembly-plugin");
        Xpp3Dom pluginConfig = new Xpp3Dom("configuration");
        Xpp3Dom attachNode = new Xpp3Dom("attach");
        attachNode.setValue("false");
        pluginConfig.addChild(attachNode);
        assemblyPlugin.setConfiguration(pluginConfig);
        Build build = new Build();
        build.setDirectory(tempDir.resolve("target").toString());
        build.addPlugin(assemblyPlugin);
        when(project.getBuild()).thenReturn(build);

        Path archivePath = tempDir.resolve("no-attach.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        Path props = createTestFile("no-attach-data.txt", "data");
        archiver.addFile(props.toFile(), "base/data.txt");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        verify(projectHelper, never()).attachArtifact(
                any(), any(String.class), any(), any(File.class));
    }

    @Test
    void attachWithOutputModeAllCallsProjectHelper() throws Exception {
        handler.setAttach(true);
        handler.setOutputMode("all");
        when(project.getArtifacts()).thenReturn(Set.of());

        Path archivePath = tempDir.resolve("attach-all.zip");
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(archivePath.toFile());
        Path props = createTestFile("all-data.txt", "data");
        archiver.addFile(props.toFile(), "base/data.txt");
        handler.finalizeArchiveCreation(archiver);
        archiver.createArchive();

        Path bomFile = tempDir.resolve("attach-all.zip.cdx.json");
        assertTrue(Files.exists(bomFile), "external BOM should be written");
        verify(projectHelper).attachArtifact(
                eq(project), eq("cdx.json"), isNull(), eq(bomFile.toFile()));
    }

    private Path createJarWithEmbeddedSbom(String jarName, String content,
            String sbomGroup, String sbomName, String sbomVersion) throws Exception {
        Bom embeddedBom = new Bom();
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(sbomGroup);
        comp.setName(sbomName);
        comp.setVersion(sbomVersion);
        comp.setBomRef("pkg:maven/" + sbomGroup + "/" + sbomName + "@" + sbomVersion);
        embeddedBom.addComponent(comp);

        Path bomJson = tempDir.resolve(jarName + ".tmp.cdx.json");
        BomWriter.writeJson(embeddedBom, bomJson, false);
        byte[] bomBytes = Files.readAllBytes(bomJson);

        Path jarPath = tempDir.resolve(jarName);
        try (JarOutputStream jos = new JarOutputStream(
                Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/sbom/bom.cdx.json"));
            jos.write(bomBytes);
            jos.closeEntry();
        }
        return jarPath;
    }

    private Path createJarWithPomProperties(String name, String groupId,
            String artifactId, String version,
            String content) throws Exception {
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

    private Path createTestJar(String name, String content) throws Exception {
        Path jarPath = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jarPath;
    }

    private Path createTestFile(String name, String content) throws Exception {
        Path path = tempDir.resolve(name);
        Files.writeString(path, content);
        return path;
    }

    private Artifact createArtifact(String groupId, String artifactId,
            String version, String type, File file) {
        return createArtifact(groupId, artifactId, version, type, "compile", file);
    }

    private Artifact createArtifact(String groupId, String artifactId,
            String version, String type, String scope, File file) {
        DefaultArtifact artifact = new DefaultArtifact(
                groupId, artifactId, version, scope, type, null,
                new DefaultArtifactHandler(type));
        artifact.setFile(file);
        return artifact;
    }

    private ZipArchiver buildArchiver(String archivePath, Path sourceFile) throws Exception {
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(tempDir.resolve("test-archive.zip").toFile());
        archiver.addFile(sourceFile.toFile(), archivePath);
        return archiver;
    }

    private Bom readBomFromArchiver(ZipArchiver archiver) throws Exception {
        archiver.createArchive();
        File zipFile = archiver.getDestFile();
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(zipFile)) {
            var entry = zf.stream()
                    .filter(e -> e.getName().endsWith(".cdx.json") || e.getName().endsWith(".cdx.xml"))
                    .findFirst().orElse(null);
            if (entry == null)
                return null;
            String json = new String(zf.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
            org.cyclonedx.parsers.JsonParser parser = new org.cyclonedx.parsers.JsonParser();
            return parser.parse(json.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Finds the first top-level BOM component matching the given type and name.
     * Returns {@code null} if the BOM is {@code null}, has no components, or no match is found.
     */
    private static Component findComponent(Bom bom, Component.Type type, String name) {
        if (bom == null || bom.getComponents() == null)
            return null;
        return bom.getComponents().stream()
                .filter(c -> c.getType() == type && name.equals(c.getName()))
                .findFirst().orElse(null);
    }

    private static DependencyCollectionContext mockCollectionContext(
            org.eclipse.aether.artifact.Artifact artifact, Dependency dependency) {
        DependencyCollectionContext ctx = mock(DependencyCollectionContext.class);
        lenient().when(ctx.getArtifact()).thenReturn(artifact);
        lenient().when(ctx.getDependency()).thenReturn(dependency);
        return ctx;
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
