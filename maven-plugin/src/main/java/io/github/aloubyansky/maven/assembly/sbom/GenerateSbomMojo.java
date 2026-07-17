package io.github.aloubyansky.maven.assembly.sbom;

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

    @Parameter(required = true, defaultValue = "${project.build.directory}/${project.build.finalName}")
    private File inputDirectory;

    @Parameter(defaultValue = "${project.build.directory}/bom.cdx.json")
    private File outputFile;

    @Parameter(defaultValue = "json")
    private String format;

    @Parameter(defaultValue = "true")
    private boolean prettyPrint;

    @Parameter(defaultValue = "SHA-256")
    private String hashAlgorithm;

    @Parameter(defaultValue = "merge")
    private String embeddedSboms;

    @Parameter
    private String externalSboms;

    @Parameter(defaultValue = "false")
    private boolean failOnMissingLicense;

    @Parameter(defaultValue = "true")
    private boolean failOnDuplicateHash;

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
                failOnDuplicateHash, failOnMissingLicense, embeddedSboms);
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
