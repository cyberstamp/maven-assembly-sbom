package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.List;

import org.apache.maven.plugin.MojoExecutionException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MergeSbomMojoTest {

    @TempDir
    Path tempDir;

    @Test
    void flatMergeAddsComponentsAtTopLevel() throws Exception {
        File base = writeBom(buildMavenBom(), "base.cdx.json");
        File external = writeBom(buildNpmBom(), "npm.cdx.json");
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(external), output, false);
        mojo.execute();

        Bom result = BomReader.readBom(output);
        assertNotNull(result);
        assertEquals(3, result.getComponents().size());
        assertTrue(result.getComponents().stream()
                .anyMatch(c -> "lib-a".equals(c.getName())));
        assertTrue(result.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())));
        assertTrue(result.getComponents().stream()
                .anyMatch(c -> "lodash".equals(c.getName())));
    }

    @Test
    void nestedMergeAddsComponentsUnderMetadataComponent() throws Exception {
        File base = writeBom(buildMavenBom(), "base.cdx.json");
        File external = writeBom(buildNpmBom(), "npm.cdx.json");
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(external), output, true);
        mojo.execute();

        Bom result = BomReader.readBom(output);
        assertNotNull(result);
        assertEquals(1, result.getComponents().size(), "top-level should only have Maven component");
        Component main = result.getMetadata().getComponent();
        assertNotNull(main.getComponents(), "metadata component should have nested components");
        assertEquals(2, main.getComponents().size());
    }

    @Test
    void flatMergeImportsDependencies() throws Exception {
        Bom baseBom = buildMavenBom();
        baseBom.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Bom npmBom = buildNpmBom();
        Dependency reactDep = new Dependency("pkg:npm/react@18.3.1");
        reactDep.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));
        npmBom.addDependency(reactDep);
        npmBom.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));

        File base = writeBom(baseBom, "base.cdx.json");
        File external = writeBom(npmBom, "npm.cdx.json");
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(external), output, false);
        mojo.execute();

        Bom result = BomReader.readBom(output);
        assertEquals(3, result.getDependencies().size());
        assertTrue(result.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/react@18.3.1".equals(d.getRef())));
    }

    @Test
    void multipleMergeBoms() throws Exception {
        File base = writeBom(buildMavenBom(), "base.cdx.json");

        Bom npm1 = new Bom();
        npm1.setComponents(new java.util.ArrayList<>(List.of(
                createComponent(null, "react", "18.3.1", "pkg:npm/react@18.3.1"))));

        Bom npm2 = new Bom();
        npm2.setComponents(new java.util.ArrayList<>(List.of(
                createComponent(null, "vue", "3.4.0", "pkg:npm/vue@3.4.0"))));

        File ext1 = writeBom(npm1, "npm1.cdx.json");
        File ext2 = writeBom(npm2, "npm2.cdx.json");
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(ext1, ext2), output, false);
        mojo.execute();

        Bom result = BomReader.readBom(output);
        assertEquals(3, result.getComponents().size());
        assertTrue(result.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())));
        assertTrue(result.getComponents().stream()
                .anyMatch(c -> "vue".equals(c.getName())));
    }

    @Test
    void failsOnMissingBaseBom() {
        File base = tempDir.resolve("nonexistent.json").toFile();
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(), output, false);
        assertThrows(MojoExecutionException.class, mojo::execute);
    }

    @Test
    void failsOnMissingMergeBom() throws Exception {
        File base = writeBom(buildMavenBom(), "base.cdx.json");
        File missing = tempDir.resolve("nonexistent.json").toFile();
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(missing), output, false);
        assertThrows(MojoExecutionException.class, mojo::execute);
    }

    @Test
    void xmlOutputFormat() throws Exception {
        File base = writeBom(buildMavenBom(), "base.cdx.json");
        File external = writeBom(buildNpmBom(), "npm.cdx.json");
        File output = tempDir.resolve("merged.cdx.xml").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(external), output, false);
        setField(mojo, "format", "xml");
        mojo.execute();

        assertTrue(output.exists());
        Bom result = BomReader.readBom(output);
        assertNotNull(result);
        assertEquals(3, result.getComponents().size());
    }

    @Test
    void nestedMergeWithExplicitParentBomRef() throws Exception {
        Bom baseBom = buildMavenBom();
        File base = writeBom(baseBom, "base.cdx.json");
        File external = writeBom(buildNpmBom(), "npm.cdx.json");
        File output = tempDir.resolve("merged.cdx.json").toFile();

        MergeSbomMojo mojo = createMojo(base, List.of(external), output, true);
        setField(mojo, "parentBomRef", "pkg:maven/org.a/lib-a@1.0");
        mojo.execute();

        Bom result = BomReader.readBom(output);
        Component libA = result.getComponents().get(0);
        assertEquals("lib-a", libA.getName());
        assertNotNull(libA.getComponents());
        assertEquals(2, libA.getComponents().size());
    }

    private Bom buildMavenBom() {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setGroup("com.example");
        main.setName("app");
        main.setVersion("1.0");
        main.setBomRef("pkg:maven/com.example/app@1.0");
        metadata.setComponent(main);
        bom.setMetadata(metadata);
        bom.setComponents(new java.util.ArrayList<>(List.of(
                createComponent("org.a", "lib-a", "1.0", "pkg:maven/org.a/lib-a@1.0"))));
        return bom;
    }

    private Bom buildNpmBom() {
        Bom bom = new Bom();
        bom.setComponents(new java.util.ArrayList<>(List.of(
                createComponent(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createComponent(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"))));
        return bom;
    }

    private static Component createComponent(String group, String name, String version,
            String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(group);
        comp.setName(name);
        comp.setVersion(version);
        comp.setBomRef(bomRef);
        comp.setPurl(bomRef);
        return comp;
    }

    private File writeBom(Bom bom, String filename) throws Exception {
        Path path = tempDir.resolve(filename);
        BomWriter.writeJson(bom, path, false);
        return path.toFile();
    }

    private MergeSbomMojo createMojo(File baseBom, List<File> mergeBoms, File outputFile,
            boolean nested) {
        MergeSbomMojo mojo = new MergeSbomMojo();
        setField(mojo, "baseSbom", baseBom);
        setField(mojo, "externalSboms", mergeBoms);
        setField(mojo, "outputFile", outputFile);
        setField(mojo, "format", "json");
        setField(mojo, "prettyPrint", true);
        setField(mojo, "nested", nested);
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
