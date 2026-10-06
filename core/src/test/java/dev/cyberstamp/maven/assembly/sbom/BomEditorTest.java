package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BomEditorTest {

    @TempDir
    Path tempDir;

    @Test
    void loadAndWriteInPlace() throws Exception {
        Path file = tempDir.resolve("in-place.cdx.json");
        Bom initial = createMinimalBom();
        BomWriter.writeJson(initial, file, true);

        String initialContent = Files.readString(file);
        Bom loadedInitial = BomReader.readBom(file);
        String initialSerial = loadedInitial.getSerialNumber();
        assertNotNull(initialSerial);

        BomEditor.load(file)
                .mutate(bom -> bom.addComponent(componentNamed("added-lib", "1.0")))
                .write();

        Bom reloaded = BomReader.readBom(file);
        assertNotNull(reloaded);
        assertEquals(1, reloaded.getComponents().size());
        assertEquals("added-lib", reloaded.getComponents().get(0).getName());
        assertNotEquals(initialSerial, reloaded.getSerialNumber(),
                "Serial number should update after mutation");
    }

    @Test
    void writeToDifferentPathLeavesSourceUntouched() throws Exception {
        Path src = tempDir.resolve("source.cdx.json");
        Path target = tempDir.resolve("subdir").resolve("target.cdx.json");
        BomWriter.writeJson(createMinimalBom(), src, true);
        String originalContent = Files.readString(src);

        BomEditor.load(src)
                .mutate(bom -> bom.addComponent(componentNamed("new-comp", "2.0")))
                .writeTo(target);

        assertEquals(originalContent, Files.readString(src),
                "Source file should remain unmodified");
        assertTrue(Files.exists(target));
        Bom targetBom = BomReader.readBom(target);
        assertEquals(1, targetBom.getComponents().size());
        assertEquals("new-comp", targetBom.getComponents().get(0).getName());
    }

    @Test
    void loadFromInputStream() throws Exception {
        Path original = tempDir.resolve("stream-src.cdx.json");
        BomWriter.writeJson(createMinimalBom(), original, true);
        byte[] bytes = Files.readAllBytes(original);

        BomEditor editor = BomEditor.load(new ByteArrayInputStream(bytes));

        // write() with no source path must fail
        assertThrows(IllegalStateException.class, editor::write);

        // writeTo(Path) succeeds
        Path out = tempDir.resolve("stream-out.cdx.json");
        editor.mutate(bom -> bom.addComponent(componentNamed("stream-lib", "1.0")))
                .writeTo(out);

        Bom result = BomReader.readBom(out);
        assertNotNull(result);
        assertEquals(1, result.getComponents().size());
        assertEquals("stream-lib", result.getComponents().get(0).getName());
    }

    @Test
    void ofBom() throws Exception {
        Bom bom = createMinimalBom();
        BomEditor editor = BomEditor.of(bom);

        assertThrows(IllegalStateException.class, editor::write);

        Path out = tempDir.resolve("of-bom.cdx.json");
        editor.bumpVersion().writeTo(out);

        Bom result = BomReader.readBom(out);
        assertNotNull(result);
        assertEquals(2, result.getVersion());
    }

    @Test
    void serialNumberIsDeterministicAndIdempotent() throws Exception {
        Path file = tempDir.resolve("idempotent.cdx.json");
        BomWriter.writeJson(createMinimalBom(), file, true);

        Bom loaded1 = BomReader.readBom(file);
        String serial1 = loaded1.getSerialNumber();

        // Writing again without mutations should produce the exact same serial number
        BomEditor.load(file).write();

        Bom loaded2 = BomReader.readBom(file);
        String serial2 = loaded2.getSerialNumber();
        assertEquals(serial1, serial2,
                "Serial number must not change when content is unchanged");
    }

    @Test
    void mergeFlat() throws Exception {
        Path baseFile = tempDir.resolve("base.cdx.json");
        Bom baseBom = createMinimalBom();
        baseBom.addComponent(componentNamed("base-lib", "1.0"));
        BomWriter.writeJson(baseBom, baseFile, true);

        Bom extraBom = createMinimalBom();
        extraBom.addComponent(componentNamed("extra-lib", "2.0"));

        BomEditor.load(baseFile)
                .mergeFlat(extraBom)
                .write();

        Bom merged = BomReader.readBom(baseFile);
        assertEquals(2, merged.getComponents().size());
        assertTrue(merged.getComponents().stream().anyMatch(c -> "base-lib".equals(c.getName())));
        assertTrue(merged.getComponents().stream().anyMatch(c -> "extra-lib".equals(c.getName())));
    }

    @Test
    void mergeUnder() throws Exception {
        Path baseFile = tempDir.resolve("parent-base.cdx.json");
        Bom baseBom = createMinimalBom();
        Component parent = componentNamed("parent-app", "1.0");
        parent.setBomRef("parent-ref");
        baseBom.addComponent(parent);
        BomWriter.writeJson(baseBom, baseFile, true);

        Bom childBom = createMinimalBom();
        childBom.addComponent(componentNamed("child-lib", "1.0"));

        BomEditor.load(baseFile)
                .mergeUnder("parent-ref", childBom)
                .write();

        Bom merged = BomReader.readBom(baseFile);
        Component parentFound = merged.getComponents().stream()
                .filter(c -> "parent-ref".equals(c.getBomRef()))
                .findFirst().orElseThrow();
        assertNotNull(parentFound.getComponents());
        assertEquals(1, parentFound.getComponents().size());
        assertEquals("child-lib", parentFound.getComponents().get(0).getName());
    }

    @Test
    void bumpVersionAndVersion() throws Exception {
        Path file = tempDir.resolve("version-test.cdx.json");
        BomWriter.writeJson(createMinimalBom(), file, true);

        BomEditor.load(file).bumpVersion().write();
        Bom v2 = BomReader.readBom(file);
        assertEquals(2, v2.getVersion());

        BomEditor.load(file).version(5).write();
        Bom v5 = BomReader.readBom(file);
        assertEquals(5, v5.getVersion());
    }

    @Test
    void formatAutoDetectedFromExtension() throws Exception {
        Path xmlFile = tempDir.resolve("out.cdx.xml");
        BomEditor.of(createMinimalBom()).writeTo(xmlFile);

        String xmlContent = Files.readString(xmlFile);
        assertTrue(xmlContent.contains("<bom"));

        Path jsonFile = tempDir.resolve("out.cdx.json");
        BomEditor.of(createMinimalBom()).writeTo(jsonFile);

        String jsonContent = Files.readString(jsonFile);
        assertTrue(jsonContent.contains("\"bomFormat\""));
    }

    @Test
    void explicitFormatAndSchemaVersion() throws Exception {
        Path file = tempDir.resolve("explicit.out");
        BomEditor.of(createMinimalBom())
                .format("xml")
                .schemaVersion(Version.VERSION_15)
                .writeTo(file);

        String content = Files.readString(file);
        assertTrue(content.contains("<bom"));
        assertTrue(content.contains("schema/bom/1.5"));
    }

    @Test
    void loadNonExistentFileThrowsNoSuchFileException() {
        Path nonExistent = tempDir.resolve("missing.cdx.json");
        assertThrows(NoSuchFileException.class, () -> BomEditor.load(nonExistent));
    }

    @Test
    void loadCorruptFileThrowsIOException() throws Exception {
        Path corrupt = tempDir.resolve("corrupt.cdx.json");
        Files.writeString(corrupt, "{ invalid json }");
        assertThrows(IOException.class, () -> BomEditor.load(corrupt));
    }

    private static Component componentNamed(String name, String version) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setVersion(version);
        comp.setBomRef(name + "-ref");
        return comp;
    }

    private static Bom createMinimalBom() {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component comp = new Component();
        comp.setType(Component.Type.APPLICATION);
        comp.setName("test-app");
        comp.setVersion("1.0.0");
        metadata.setComponent(comp);
        bom.setMetadata(metadata);
        return bom;
    }
}
