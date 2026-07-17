package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencySelector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GenerateSbomMojoTest {

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

    private Path inputDir;

    @BeforeEach
    void setUp() throws Exception {
        inputDir = tempDir.resolve("exploded-war");
        Files.createDirectories(inputDir.resolve("WEB-INF/lib"));

        lenient().when(project.getGroupId()).thenReturn("com.example");
        lenient().when(project.getArtifactId()).thenReturn("test-app");
        lenient().when(project.getVersion()).thenReturn("1.0");
        lenient().when(project.getPackaging()).thenReturn("jar");
        lenient().when(project.getBasedir()).thenReturn(tempDir.toFile());
        Build build = new Build();
        build.setDirectory(tempDir.resolve("target").toString());
        lenient().when(project.getBuild()).thenReturn(build);
        lenient().when(session.getRepositorySession()).thenReturn(repoSession);
        DependencySelector selector = mock(DependencySelector.class);
        lenient().when(selector.selectDependency(any())).thenReturn(true);
        lenient().when(selector.deriveChildSelector(any())).thenReturn(selector);
        lenient().when(repoSession.getDependencySelector()).thenReturn(selector);
        lenient().when(session.getProjects()).thenReturn(List.of());
    }

    @Test
    void scansDirectoryAndProducessBom() throws Exception {
        Path jarFile = createTestJar("WEB-INF/lib/foo-1.0.jar", "foo-content");
        Artifact artifact = createArtifact("org.example", "foo", "1.0",
                "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        File output = tempDir.resolve("output.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        mojo.execute();

        assertTrue(output.exists());
        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
        assertNotNull(bom.getMetadata());
        assertEquals("test-app", bom.getMetadata().getComponent().getName());

        Component foo = bom.getComponents().stream()
                .filter(c -> "foo".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(foo, "should find foo as a component");
        assertEquals(Component.Type.LIBRARY, foo.getType());
        assertNotNull(foo.getEvidence());
        assertEquals("WEB-INF/lib/foo-1.0.jar",
                foo.getEvidence().getOccurrences().get(0).getLocation());
    }

    @Test
    void unmatchedFilesIncludedAsFileComponents() throws Exception {
        Files.writeString(inputDir.resolve("WEB-INF/web.xml"), "<web-app/>");
        when(project.getArtifacts()).thenReturn(Set.of());

        File output = tempDir.resolve("output.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
        Component fileComp = bom.getComponents().stream()
                .filter(c -> c.getType() == Component.Type.FILE)
                .findFirst().orElse(null);
        assertNotNull(fileComp, "unmatched file should appear as FILE component");
    }

    @Test
    void mergesExternalSbom() throws Exception {
        Path jarFile = createTestJar("WEB-INF/lib/foo-1.0.jar", "foo-content");
        Artifact artifact = createArtifact("org.example", "foo", "1.0",
                "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        Bom npmBom = new Bom();
        Component react = new Component();
        react.setType(Component.Type.LIBRARY);
        react.setName("react");
        react.setVersion("18.3.1");
        react.setBomRef("pkg:npm/react@18.3.1");
        react.setPurl("pkg:npm/react@18.3.1");
        npmBom.setComponents(new java.util.ArrayList<>(List.of(react)));
        Path npmBomFile = tempDir.resolve("npm-bom.cdx.json");
        BomWriter.writeJson(npmBom, npmBomFile, false);

        File output = tempDir.resolve("output.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        setField(mojo, "externalSboms", npmBomFile.toString());
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        Component main = bom.getMetadata().getComponent();
        assertNull(main.getComponents(),
                "external SBOM components should not be nested under main");
        assertTrue(bom.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())),
                "external SBOM components should be flat top-level peers");
    }

    @Test
    void warPackagingIncludesTypeInPurl() throws Exception {
        when(project.getPackaging()).thenReturn("war");
        Files.writeString(inputDir.resolve("WEB-INF/web.xml"), "<web-app/>");
        when(project.getArtifacts()).thenReturn(Set.of());

        File output = tempDir.resolve("output.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        String purl = bom.getMetadata().getComponent().getPurl();
        assertTrue(purl.contains("?type=war"),
                "WAR packaging should produce purl with ?type=war, got: " + purl);
    }

    @Test
    void jarPackagingOmitsTypeFromPurl() throws Exception {
        when(project.getPackaging()).thenReturn("jar");
        Files.writeString(inputDir.resolve("data.txt"), "hello");
        when(project.getArtifacts()).thenReturn(Set.of());

        File output = tempDir.resolve("output.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        String purl = bom.getMetadata().getComponent().getPurl();
        assertFalse(purl.contains("?type="),
                "JAR packaging should not include type qualifier, got: " + purl);
    }

    @Test
    void failsOnMissingInputDirectory() {
        File output = tempDir.resolve("output.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        setField(mojo, "inputDirectory",
                tempDir.resolve("nonexistent").toFile());

        assertThrows(MojoExecutionException.class, mojo::execute);
    }

    @Test
    void xmlFormat() throws Exception {
        Files.writeString(inputDir.resolve("data.txt"), "hello");
        when(project.getArtifacts()).thenReturn(Set.of());

        File output = tempDir.resolve("output.cdx.xml").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        setField(mojo, "format", "xml");
        mojo.execute();

        assertTrue(output.exists());
        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
    }

    @Test
    void embeddedSbomHandlingIgnoreSkipsDetection() throws Exception {
        Path jarFile = createJarWithEmbeddedSbom("WEB-INF/lib/plugin-1.0.jar",
                "plugin-data", "org.plugin", "plugin-lib", "1.0");
        Artifact artifact = createArtifact("org.example", "plugin", "1.0",
                "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        File output = tempDir.resolve("output-ignore.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        setField(mojo, "embeddedSboms", "ignore");
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
        Component plugin = bom.getComponents().stream()
                .filter(c -> "plugin".equals(c.getName()) && c.getType() == Component.Type.LIBRARY)
                .findFirst().orElse(null);
        assertNotNull(plugin, "JAR should still be detected as LIBRARY");
        assertTrue(plugin.getComponents() == null || plugin.getComponents().isEmpty(),
                "embedded SBOM components should NOT be merged when handling=ignore");
    }

    @Test
    void detectEmbeddedSbomsFromJarInDirectory() throws Exception {
        Path jarFile = createJarWithEmbeddedSbom("WEB-INF/lib/plugin-1.0.jar",
                "plugin-data", "org.plugin", "plugin-lib", "1.0");
        Artifact artifact = createArtifact("org.example", "plugin", "1.0",
                "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        File output = tempDir.resolve("output-merge.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
        Component plugin = bom.getComponents().stream()
                .filter(c -> "plugin".equals(c.getName()) && c.getType() == Component.Type.LIBRARY)
                .findFirst().orElse(null);
        assertNotNull(plugin, "JAR should be detected as LIBRARY");
        assertNotNull(plugin.getComponents(),
                "embedded SBOM components should be merged under JAR");
        assertTrue(plugin.getComponents().stream()
                .anyMatch(c -> "plugin-lib".equals(c.getName())),
                "embedded SBOM library should appear as nested component");
    }

    @Test
    void embeddedSbomHandlingLinkAddsReference() throws Exception {
        Path jarFile = createJarWithEmbeddedSbom("WEB-INF/lib/plugin-1.0.jar",
                "plugin-data", "org.plugin", "plugin-lib", "1.0");
        Artifact artifact = createArtifact("org.example", "plugin", "1.0",
                "jar", jarFile.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        File output = tempDir.resolve("output-link.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        setField(mojo, "embeddedSboms", "link");
        mojo.execute();

        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
        Component plugin = bom.getComponents().stream()
                .filter(c -> "plugin".equals(c.getName()) && c.getType() == Component.Type.LIBRARY)
                .findFirst().orElse(null);
        assertNotNull(plugin, "JAR should be detected as LIBRARY");
        assertTrue(plugin.getComponents() == null || plugin.getComponents().isEmpty(),
                "embedded SBOM components should NOT be merged in link mode");
        assertNotNull(plugin.getExternalReferences(),
                "link mode should add external BOM reference");
        assertTrue(plugin.getExternalReferences().stream()
                .anyMatch(r -> r.getType() == org.cyclonedx.model.ExternalReference.Type.BOM),
                "external reference should be of type BOM");
    }

    @Test
    void dependencyGraphFailureDoesNotPreventBomGeneration() throws Exception {
        Files.writeString(inputDir.resolve("data.txt"), "hello");
        when(project.getArtifacts()).thenReturn(Set.of());
        when(repoSystem.collectDependencies(any(), any()))
                .thenThrow(new RuntimeException("simulated collection failure"));

        File output = tempDir.resolve("output-depfail.cdx.json").toFile();
        GenerateSbomMojo mojo = createMojo(output);
        mojo.execute();

        assertTrue(output.exists(), "BOM should still be generated despite dependency graph failure");
        Bom bom = BomReader.readBom(output);
        assertNotNull(bom);
        assertNotNull(bom.getMetadata());
        assertEquals("test-app", bom.getMetadata().getComponent().getName());
    }

    private Path createJarWithEmbeddedSbom(String relativePath, String content,
            String sbomGroup, String sbomName, String sbomVersion) throws Exception {
        Bom embeddedBom = new Bom();
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(sbomGroup);
        comp.setName(sbomName);
        comp.setVersion(sbomVersion);
        comp.setBomRef("pkg:maven/" + sbomGroup + "/" + sbomName + "@" + sbomVersion);
        embeddedBom.addComponent(comp);

        Path bomJson = tempDir.resolve("tmp-embedded.cdx.json");
        BomWriter.writeJson(embeddedBom, bomJson, false);
        byte[] bomBytes = java.nio.file.Files.readAllBytes(bomJson);

        Path jarPath = inputDir.resolve(relativePath);
        java.nio.file.Files.createDirectories(jarPath.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("META-INF/sbom/bom.cdx.json"));
            jos.write(bomBytes);
            jos.closeEntry();
        }
        return jarPath;
    }

    private Path createTestJar(String relativePath, String content) throws Exception {
        Path jarPath = inputDir.resolve(relativePath);
        Files.createDirectories(jarPath.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jarPath;
    }

    private Artifact createArtifact(String groupId, String artifactId,
            String version, String type, File file) {
        DefaultArtifact artifact = new DefaultArtifact(
                groupId, artifactId, version, "compile", type, null,
                new DefaultArtifactHandler(type));
        artifact.setFile(file);
        return artifact;
    }

    private GenerateSbomMojo createMojo(File output) {
        GenerateSbomMojo mojo = new GenerateSbomMojo();
        setField(mojo, "project", project);
        setField(mojo, "session", session);
        setField(mojo, "repoSystem", repoSystem);
        setField(mojo, "effectiveModelResolver", effectiveModelResolver);
        setField(mojo, "inputDirectory", inputDir.toFile());
        setField(mojo, "outputFile", output);
        setField(mojo, "format", "json");
        setField(mojo, "prettyPrint", true);
        setField(mojo, "hashAlgorithm", "SHA-256");
        setField(mojo, "embeddedSboms", "merge");
        setField(mojo, "failOnMissingLicense", false);
        setField(mojo, "failOnDuplicateHash", true);
        return mojo;
    }

    private static void setField(Object target, String name, Object value) {
        try {
            Field field = target.getClass().getDeclaredField(name);
            field.setAccessible(true);
            field.set(target, value);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException("Failed to set field " + name, e);
        }
    }
}
