package dev.cyberstamp.maven.assembly.sbom;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Bom;

/**
 * Serializes a CycloneDX {@link Bom} to disk in JSON or XML format.
 *
 * <p>
 * Before writing, a content-based serial number is computed and set on the BOM
 * using the same schema version that drives serialization, so the two always
 * stay in sync.
 * </p>
 *
 * <p>
 * The class is a stateless utility and cannot be instantiated.
 * </p>
 */
public final class BomWriter {

    private BomWriter() {
    }

    public static void writeJson(Bom bom, Path output, boolean prettyPrint)
            throws IOException, GeneratorException {
        writeJson(bom, output, prettyPrint, null);
    }

    public static void writeJson(Bom bom, Path output, boolean prettyPrint, Version schemaVersion)
            throws IOException, GeneratorException {
        schemaVersion = resolveVersion(schemaVersion);
        setSerialNumber(bom, schemaVersion);
        BomJsonGenerator generator = BomGeneratorFactory.createJson(schemaVersion, bom);
        Files.writeString(output, generator.toJsonString(prettyPrint), StandardCharsets.UTF_8);
    }

    public static void writeXml(Bom bom, Path output) throws IOException, GeneratorException {
        writeXml(bom, output, null);
    }

    public static void writeXml(Bom bom, Path output, Version schemaVersion)
            throws IOException, GeneratorException {
        schemaVersion = resolveVersion(schemaVersion);
        setSerialNumber(bom, schemaVersion);
        BomXmlGenerator generator = BomGeneratorFactory.createXml(schemaVersion, bom);
        Files.writeString(output, generator.toXmlString(), StandardCharsets.UTF_8);
    }

    public static void write(Bom bom, Path output, String format, boolean prettyPrint)
            throws IOException, GeneratorException {
        write(bom, output, format, prettyPrint, null);
    }

    public static void write(Bom bom, Path output, String format, boolean prettyPrint,
            Version schemaVersion) throws IOException, GeneratorException {
        if ("xml".equalsIgnoreCase(format)) {
            writeXml(bom, output, schemaVersion);
        } else {
            writeJson(bom, output, prettyPrint, schemaVersion);
        }
    }

    private static Version resolveVersion(Version schemaVersion) {
        return schemaVersion != null ? schemaVersion : SchemaVersions.latest();
    }

    private static void setSerialNumber(Bom bom, Version schemaVersion) {
        schemaVersion = resolveVersion(schemaVersion);
        bom.setSerialNumber(null);
        final String json;
        try {
            json = BomGeneratorFactory.createJson(schemaVersion, bom).toJsonString(false);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize the SBOM to compute its serial number", e);
        }
        bom.setSerialNumber("urn:uuid:" + UUID.nameUUIDFromBytes(json.getBytes(StandardCharsets.UTF_8)));
    }
}
