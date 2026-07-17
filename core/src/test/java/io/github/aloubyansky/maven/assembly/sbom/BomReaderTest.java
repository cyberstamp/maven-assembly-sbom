package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BomReaderTest {

    private static final String MINIMAL_JSON_BOM = """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
              "components": [
                {
                  "type": "library",
                  "name": "react",
                  "version": "18.3.1",
                  "purl": "pkg:npm/react@18.3.1",
                  "bom-ref": "pkg:npm/react@18.3.1"
                }
              ]
            }
            """;

    private static final String MINIMAL_XML_BOM = """
            <?xml version="1.0" encoding="UTF-8"?>
            <bom xmlns="http://cyclonedx.org/schema/bom/1.6"
                 serialNumber="urn:uuid:00000000-0000-0000-0000-000000000002">
              <components>
                <component type="library">
                  <name>lodash</name>
                  <version>4.17.21</version>
                  <purl>pkg:npm/lodash@4.17.21</purl>
                </component>
              </components>
            </bom>
            """;

    @TempDir
    Path tempDir;

    @Test
    void readJsonBomFromFile() throws IOException {
        File file = writeTemp("bom.cdx.json", MINIMAL_JSON_BOM);
        Bom bom = BomReader.readBom(file);

        assertNotNull(bom);
        assertEquals(1, bom.getComponents().size());
        assertEquals("react", bom.getComponents().get(0).getName());
        assertEquals("18.3.1", bom.getComponents().get(0).getVersion());
    }

    @Test
    void readXmlBomFromFile() throws IOException {
        File file = writeTemp("bom.cdx.xml", MINIMAL_XML_BOM);
        Bom bom = BomReader.readBom(file);

        assertNotNull(bom);
        assertEquals(1, bom.getComponents().size());
        assertEquals("lodash", bom.getComponents().get(0).getName());
    }

    @Test
    void readJsonBomFromInputStream() throws IOException {
        var is = new ByteArrayInputStream(MINIMAL_JSON_BOM.getBytes(StandardCharsets.UTF_8));
        Bom bom = BomReader.readBom(is);

        assertNotNull(bom);
        assertEquals(1, bom.getComponents().size());
        assertEquals("react", bom.getComponents().get(0).getName());
    }

    @Test
    void readInvalidFileReturnsNull() throws IOException {
        File file = writeTemp("not-a-bom.txt", "this is not a bom at all");
        Bom bom = BomReader.readBom(file);

        assertNull(bom);
    }

    @Test
    void isSbomFileDetectsCdxJsonExtension() {
        assertTrue(BomReader.isSbomFile("bom.cdx.json"));
        assertTrue(BomReader.isSbomFile("path/to/bom.cdx.json"));
        assertTrue(BomReader.isSbomFile("web/console.war/bom.cdx.json"));
    }

    @Test
    void isSbomFileDetectsCdxXmlExtension() {
        assertTrue(BomReader.isSbomFile("bom.cdx.xml"));
        assertTrue(BomReader.isSbomFile("path/to/bom.cdx.xml"));
    }

    @Test
    void isSbomFileRejectsNonSbomFiles() {
        assertFalse(BomReader.isSbomFile("bom.json"));
        assertFalse(BomReader.isSbomFile("bom.xml"));
        assertFalse(BomReader.isSbomFile("lib/foo.jar"));
        assertFalse(BomReader.isSbomFile("conf/app.properties"));
        assertFalse(BomReader.isSbomFile("cdx.json"));
    }

    @Test
    void sbomStemStripsJsonExtension() {
        assertEquals("bom", BomReader.sbomStem("bom.cdx.json"));
        assertEquals("path/to/bom", BomReader.sbomStem("path/to/bom.cdx.json"));
    }

    @Test
    void sbomStemStripsXmlExtension() {
        assertEquals("bom", BomReader.sbomStem("bom.cdx.xml"));
        assertEquals("path/to/bom", BomReader.sbomStem("path/to/bom.cdx.xml"));
    }

    @Test
    void sbomStemJsonAndXmlProduceSameKey() {
        assertEquals(
                BomReader.sbomStem("web/console.war/bom.cdx.json"),
                BomReader.sbomStem("web/console.war/bom.cdx.xml"));
    }

    @Test
    void sbomStemReturnsOriginalForNonSbom() {
        assertEquals("lib/foo.jar", BomReader.sbomStem("lib/foo.jar"));
    }

    private File writeTemp(String name, String content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file.toFile();
    }
}
