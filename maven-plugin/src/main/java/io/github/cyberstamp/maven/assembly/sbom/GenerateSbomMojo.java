package io.github.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Hash;
import org.eclipse.aether.RepositorySystem;

/**
 * Scans an exploded directory (e.g., an exploded WAR produced by
 * {@code maven-war-plugin}) and generates a CycloneDX SBOM by
 * identifying Maven artifacts via content-hash matching.
 *
 * <p>
 * Detected embedded SBOMs are merged or linked according to the
 * {@code embeddedSboms} parameter. Additional external
 * SBOMs (e.g., an npm SBOM) can be merged via {@code externalSboms}.
 * </p>
 */
@Mojo(name = "generate", defaultPhase = LifecyclePhase.PREPARE_PACKAGE, requiresDependencyResolution = ResolutionScope.RUNTIME)
public class GenerateSbomMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session}", readonly = true)
    private MavenSession session;

    @Component
    private RepositorySystem repoSystem;

    @Component
    private EffectiveModelResolver effectiveModelResolver;

    @Component
    private MavenProjectHelper projectHelper;

    /**
     * The exploded directory to scan for artifact identification
     * (e.g., an exploded WAR produced by {@code maven-war-plugin}).
     */
    @Parameter(required = true, defaultValue = "${project.build.directory}/${project.build.finalName}")
    private File inputDirectory;

    /** Path where the generated SBOM will be written. */
    @Parameter(defaultValue = "${project.build.directory}/bom.cdx.json")
    private File outputFile;

    /** Output format: {@code "json"} or {@code "xml"}. */
    @Parameter(defaultValue = "json")
    private String format;

    /** Whether to indent the output for readability. */
    @Parameter(defaultValue = "true")
    private boolean prettyPrint;

    /**
     * Hash algorithm for content hashes. Must be supported by both
     * {@link java.security.MessageDigest} and the CycloneDX specification.
     */
    @Parameter(defaultValue = "SHA-256")
    private String hashAlgorithm;

    /**
     * How to handle CycloneDX SBOM files found inside scanned
     * artifacts: {@code "merge"} (import as nested sub-components),
     * {@code "link"} (add an external reference), or {@code "ignore"}.
     */
    @Parameter(defaultValue = "merge")
    private String embeddedSboms;

    /**
     * Comma-separated paths to external CycloneDX SBOMs to merge
     * into the generated SBOM. Relative paths are resolved against
     * the project base directory.
     */
    @Parameter
    private String externalSboms;

    /**
     * When {@code true}, the build fails if any library component
     * has no license information in its effective POM.
     */
    @Parameter(defaultValue = "false")
    private boolean failOnMissingLicense;

    /**
     * When {@code true}, the build fails if two distinct artifacts
     * have identical content hashes.
     */
    @Parameter(defaultValue = "true")
    private boolean failOnDuplicateHash;

    /**
     * When {@code true}, generic file components are removed from
     * the output, keeping only library components.
     */
    @Parameter(defaultValue = "false")
    private boolean librariesOnly;

    /**
     * Attaches the generated SBOM as a Maven project artifact with
     * type {@code cdx.json} or {@code cdx.xml} and classifier
     * {@code cyclonedx}.
     */
    @Parameter(defaultValue = "false")
    private boolean attach;

    /**
     * User-configurable metadata (CPE, description, supplier,
     * manufacturer, publisher, copyright) for the main BOM component.
     */
    @Parameter
    private ProductInfo product;

    @Override
    public void execute() throws MojoExecutionException {
        if (!inputDirectory.isDirectory()) {
            throw new MojoExecutionException(
                    "Input directory does not exist: " + inputDirectory);
        }

        Hash.Algorithm bomHashAlgorithm;
        try {
            bomHashAlgorithm = Hash.Algorithm.fromSpec(hashAlgorithm);
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException(
                    "Hash algorithm '" + hashAlgorithm
                            + "' is not supported by the CycloneDX specification",
                    e);
        }
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new MojoExecutionException(
                    "Unsupported hash algorithm: " + hashAlgorithm, e);
        }

        List<Bom> externalBomList = SbomGenerator.parseExternalBoms(
                externalSboms, project.getBasedir().toPath());

        List<ArchiveContent.FileEntry> entries;
        try {
            entries = collectDirectoryEntries(inputDirectory.toPath(), messageDigest);
        } catch (IOException e) {
            throw new MojoExecutionException(
                    "Failed to scan directory: " + inputDirectory, e);
        }
        getLog().info("Scanned " + entries.size() + " files in " + inputDirectory);

        SbomGenerator generator = new SbomGenerator(
                project, session, repoSystem, effectiveModelResolver,
                messageDigest, bomHashAlgorithm,
                failOnDuplicateHash, failOnMissingLicense, embeddedSboms,
                librariesOnly);
        generator.setProduct(product);
        Bom bom = generator.generate(entries, null, externalBomList,
                null, null, project.getPackaging());

        if (outputFile.getParentFile() != null) {
            outputFile.getParentFile().mkdirs();
        }
        try {
            BomWriter.write(bom, outputFile.toPath(), format, prettyPrint);
        } catch (Exception e) {
            throw new MojoExecutionException(
                    "Failed to write SBOM to " + outputFile, e);
        }

        int componentCount = bom.getComponents() != null ? bom.getComponents().size() : 0;
        getLog().info("SBOM with " + componentCount + " components written to " + outputFile);

        if (attach) {
            String type = "xml".equalsIgnoreCase(format) ? "cdx.xml" : "cdx.json";
            projectHelper.attachArtifact(project, type, "cyclonedx", outputFile);
            getLog().info("Attached SBOM artifact: type=" + type + ", classifier=cyclonedx");
        }
    }

    private List<ArchiveContent.FileEntry> collectDirectoryEntries(
            Path dir, MessageDigest digest) throws IOException {
        List<ArchiveContent.FileEntry> entries = new ArrayList<>();
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                String relativePath = dir.relativize(file).toString().replace('\\', '/');
                String hash = SbomUtils.computeHash(digest, file);
                entries.add(new ArchiveContent.FileEntry(
                        relativePath, hash, file.toFile()));
                return FileVisitResult.CONTINUE;
            }
        });
        return entries;
    }
}
