package io.github.aloubyansky.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads CycloneDX Bill of Materials (SBOM) files in JSON or XML format.
 *
 * <p>
 * Format detection is automatic — the first byte of the content
 * determines whether the JSON or XML parser is used.
 * </p>
 */
public final class BomReader {

    private static final Logger log = LoggerFactory.getLogger(BomReader.class);

    private BomReader() {
    }

    /**
     * Parses a CycloneDX BOM from a file on disk.
     *
     * @param file the BOM file (JSON or XML)
     * @return the parsed BOM, or {@code null} if parsing fails
     */
    public static Bom readBom(File file) {
        try {
            Parser parser = BomParserFactory.createParser(file);
            return parser.parse(file);
        } catch (ParseException e) {
            log.warn("Failed to parse SBOM file {}", file, e);
            return null;
        }
    }

    /**
     * Parses a CycloneDX BOM from an input stream.
     *
     * <p>
     * The stream is read fully into memory before parsing. The caller
     * is responsible for closing the stream.
     * </p>
     *
     * @param inputStream the BOM content (JSON or XML)
     * @return the parsed BOM, or {@code null} if parsing fails
     * @throws IOException if the stream cannot be read
     */
    public static Bom readBom(InputStream inputStream) throws IOException {
        byte[] bytes = inputStream.readAllBytes();
        try {
            Parser parser = BomParserFactory.createParser(bytes);
            return parser.parse(bytes);
        } catch (ParseException e) {
            log.warn("Failed to parse SBOM from stream", e);
            return null;
        }
    }

    /**
     * Returns {@code true} if the path has a CycloneDX SBOM file extension.
     *
     * <p>
     * Recognized extensions are {@code .cdx.json} and {@code .cdx.xml}.
     * </p>
     *
     * @param path the file path or archive entry name
     * @return {@code true} if the path looks like a CycloneDX SBOM
     */
    static boolean isSbomFile(String path) {
        return path.endsWith(".cdx.json") || path.endsWith(".cdx.xml");
    }

    /**
     * Extracts the SBOM stem from a path for deduplication.
     *
     * <p>
     * Strips the {@code .cdx.json} or {@code .cdx.xml} suffix to produce
     * a key that can be compared across format variants. For example,
     * {@code "web/console.war/bom.cdx.json"} and
     * {@code "web/console.war/bom.cdx.xml"} both produce
     * {@code "web/console.war/bom"}.
     * </p>
     *
     * @param path the SBOM file path
     * @return the path without the CycloneDX extension, or the original
     *         path if no recognized extension is found
     */
    static String sbomStem(String path) {
        if (path.endsWith(".cdx.json")) {
            return path.substring(0, path.length() - ".cdx.json".length());
        }
        if (path.endsWith(".cdx.xml")) {
            return path.substring(0, path.length() - ".cdx.xml".length());
        }
        return path;
    }
}
