package dev.cyberstamp.maven.assembly.sbom;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Consumer;

import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.model.Bom;

/**
 * Fluent API for loading, modifying, and persisting CycloneDX BOMs.
 *
 * <p>
 * Modifications can be applied directly to the underlying {@link Bom} via
 * {@link #mutate(Consumer)} or through high-level operations like
 * {@link #mergeFlat(Bom)} and {@link #mergeUnder(String, Bom)}.
 * </p>
 *
 * <p>
 * When saved to disk via {@link #write()} or {@link #writeTo(Path)}, the
 * BOM's {@code serialNumber} is automatically recomputed as a deterministic
 * hash of the updated content.
 * </p>
 */
public final class BomEditor {

    private final Path sourcePath;
    private final Bom bom;

    private Version schemaVersion;
    private Boolean prettyPrint;
    private String format;

    private BomEditor(Path sourcePath, Bom bom) {
        this.sourcePath = sourcePath;
        this.bom = Objects.requireNonNull(bom, "bom must not be null");
    }

    /**
     * Loads an existing CycloneDX BOM from disk.
     *
     * @param path the path to the BOM file (JSON or XML)
     * @return a new editor initialized with the parsed BOM
     * @throws NoSuchFileException if the file does not exist
     * @throws IOException if the file cannot be read or parsed
     */
    public static BomEditor load(Path path) throws IOException {
        Objects.requireNonNull(path, "path must not be null");
        if (!Files.isRegularFile(path)) {
            throw new NoSuchFileException(path.toString());
        }
        Bom bom = BomReader.readBom(path);
        if (bom == null) {
            throw new IOException("Failed to parse CycloneDX BOM from " + path);
        }
        return new BomEditor(path, bom);
    }

    /**
     * Loads a CycloneDX BOM from an input stream.
     *
     * <p>
     * Note that editors created from an input stream do not track a source path,
     * so {@link #write()} cannot be used; use {@link #writeTo(Path)} instead.
     * </p>
     *
     * @param inputStream the stream containing the BOM content (JSON or XML)
     * @return a new editor initialized with the parsed BOM
     * @throws IOException if the stream cannot be read or parsed
     */
    public static BomEditor load(InputStream inputStream) throws IOException {
        Objects.requireNonNull(inputStream, "inputStream must not be null");
        Bom bom = BomReader.readBom(inputStream);
        if (bom == null) {
            throw new IOException("Failed to parse CycloneDX BOM from input stream");
        }
        return new BomEditor(null, bom);
    }

    /**
     * Creates an editor wrapping an existing {@link Bom} instance.
     *
     * @param bom the BOM to edit
     * @return a new editor
     */
    public static BomEditor of(Bom bom) {
        return new BomEditor(null, bom);
    }

    /**
     * Applies a mutation function to the underlying {@link Bom}.
     *
     * @param mutator consumer that receives and modifies the BOM
     * @return this editor
     */
    public BomEditor mutate(Consumer<Bom> mutator) {
        Objects.requireNonNull(mutator, "mutator must not be null");
        mutator.accept(bom);
        return this;
    }

    /**
     * Merges components and dependencies from another BOM into this BOM at the top level.
     *
     * @param other the BOM whose components to merge
     * @return this editor
     */
    public BomEditor mergeFlat(Bom other) {
        Objects.requireNonNull(other, "other must not be null");
        BomMerger.mergeFlat(bom, other);
        return this;
    }

    /**
     * Merges components from another BOM under the specified parent component.
     *
     * @param parentBomRef the {@code bom-ref} of the component under which to nest
     * @param other the BOM whose components to merge
     * @return this editor
     */
    public BomEditor mergeUnder(String parentBomRef, Bom other) {
        Objects.requireNonNull(other, "other must not be null");
        BomMerger.mergeUnder(bom, parentBomRef, other);
        return this;
    }

    /**
     * Increments the BOM's {@code version} counter by 1 (or sets it to 1 if not previously set).
     *
     * @return this editor
     */
    public BomEditor bumpVersion() {
        bom.setVersion(bom.getVersion() <= 0 ? 1 : bom.getVersion() + 1);
        return this;
    }

    /**
     * Sets the BOM's {@code version} counter explicitly.
     *
     * @param version the version number to set
     * @return this editor
     */
    public BomEditor version(int version) {
        bom.setVersion(version);
        return this;
    }

    /**
     * Configures the CycloneDX schema version to use when serializing.
     *
     * @param schemaVersion the schema version, or {@code null} for the default latest version
     * @return this editor
     */
    public BomEditor schemaVersion(Version schemaVersion) {
        this.schemaVersion = schemaVersion;
        return this;
    }

    /**
     * Configures the CycloneDX schema version to use when serializing.
     *
     * @param schemaVersion the schema version string, e.g. {@code "1.5"} or {@code "1.6"}
     * @return this editor
     */
    public BomEditor schemaVersion(String schemaVersion) {
        this.schemaVersion = SchemaVersions.resolve(schemaVersion);
        return this;
    }

    /**
     * Configures whether JSON output should be pretty-printed. Defaults to {@code true}.
     *
     * @param prettyPrint whether to pretty-print
     * @return this editor
     */
    public BomEditor prettyPrint(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
        return this;
    }

    /**
     * Configures the output format ({@code "json"} or {@code "xml"}).
     * If not set, format is inferred from the target file name extension.
     *
     * @param format the output format, or {@code null} for auto-detection
     * @return this editor
     */
    public BomEditor format(String format) {
        this.format = format;
        return this;
    }

    /**
     * Persists the BOM back to its source path, automatically recomputing the serial number.
     *
     * @throws IllegalStateException if this editor was not loaded from a file/path
     * @throws IOException if writing fails
     * @throws GeneratorException if BOM serialization fails
     */
    public void write() throws IOException, GeneratorException {
        if (sourcePath == null) {
            throw new IllegalStateException("Cannot write in-place: no source path was specified");
        }
        writeTo(sourcePath);
    }

    /**
     * Persists the BOM to the specified target path, automatically recomputing the serial number.
     *
     * @param targetPath path where the BOM will be written
     * @throws IOException if writing fails
     * @throws GeneratorException if BOM serialization fails
     */
    public void writeTo(Path targetPath) throws IOException, GeneratorException {
        Objects.requireNonNull(targetPath, "targetPath must not be null");
        Path parent = targetPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String effectiveFormat = format;
        if (effectiveFormat == null) {
            effectiveFormat = isXml(targetPath) ? "xml" : "json";
        }
        boolean effectivePrettyPrint = prettyPrint != null ? prettyPrint : true;
        BomWriter.write(bom, targetPath, effectiveFormat, effectivePrettyPrint, schemaVersion);
    }

    private static boolean isXml(Path path) {
        Path fileName = path.getFileName();
        if (fileName == null) {
            return false;
        }
        return fileName.toString().toLowerCase().endsWith(".xml");
    }
}
