package dev.cyberstamp.maven.assembly.sbom;

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
import org.apache.maven.settings.Server;
import org.apache.maven.settings.crypto.DefaultSettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;
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

    @Component
    private SettingsDecrypter settingsDecrypter;

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
     * When {@code true}, components this plugin identifies carry CycloneDX
     * identity evidence recording how they were identified. When
     * {@code false}, this plugin emits no identity evidence of its own;
     * identity evidence from external or embedded SBOMs is preserved, and
     * occurrences are unaffected.
     */
    @Parameter(defaultValue = "true")
    private boolean identityEvidence;

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
     * CycloneDX schema version to use for SBOM output and serial-number
     * computation, e.g. {@code "1.5"} or {@code "1.6"}.
     *
     * <p>
     * When omitted, the latest version supported by the integrated
     * CycloneDX Java library is used automatically. Set this explicitly
     * only when you need to produce output compatible with a tool that
     * does not yet consume the latest schema version.
     * </p>
     */
    @Parameter
    private String schemaVersion;

    /**
     * User-configurable metadata (CPE, description, supplier,
     * manufacturer, publisher, copyright) for the main BOM component.
     */
    @Parameter
    private ProductInfo product;

    /**
     * Settings for identifying non-Maven-built archive entries (e.g. jars
     * built with Gradle or Ant) by resolving their Maven coordinates from
     * Maven Central and/or an internal Nexus or Artifactory instance, keyed
     * by the entry's SHA-1 content hash. Disabled by default.
     */
    @Parameter
    private RemoteArtifactLookup remoteLookup;

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

        // If the output file exists from a previous build, remember its hash
        // so we can exclude stale copies from the scan (e.g. a WAR plugin may
        // have copied the old SBOM into the exploded directory before we run).
        String previousOutputHash = null;
        if (outputFile.isFile()) {
            try {
                previousOutputHash = SbomUtils.computeHash(messageDigest, outputFile.toPath());
            } catch (IOException e) {
                getLog().debug("Could not hash previous output file: " + e.getMessage());
            }
        }

        List<FileEntry> entries;
        try {
            entries = collectDirectoryEntries(inputDirectory.toPath(), messageDigest);
        } catch (IOException e) {
            throw new MojoExecutionException(
                    "Failed to scan directory: " + inputDirectory, e);
        }
        if (previousOutputHash != null) {
            String excludeHash = previousOutputHash;
            entries.removeIf(e -> excludeHash.equals(e.hash()));
        }
        getLog().info("Scanned " + entries.size() + " files in " + inputDirectory);

        SbomGenerator generator = new SbomGenerator(
                project, session, repoSystem, effectiveModelResolver,
                messageDigest, bomHashAlgorithm,
                failOnDuplicateHash, failOnMissingLicense, embeddedSboms,
                librariesOnly, schemaVersion);
        generator.setProduct(product);
        generator.setIdentityEvidence(identityEvidence);
        generator.setRemoteCoordinatesResolver(buildRemoteCoordinatesResolver());
        Bom bom = generator.generate(entries, null, externalBomList,
                null, null, project.getPackaging());

        if (outputFile.getParentFile() != null) {
            outputFile.getParentFile().mkdirs();
        }
        try {
            BomWriter.write(bom, outputFile.toPath(), format, prettyPrint,
                    generator.getSchemaVersion());
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

    /**
     * Builds the remote checksum lookup resolver from {@link #remoteLookup},
     * resolving any {@code settings.xml} server credentials it references.
     *
     * @return the resolver, or {@code null} if remote lookup is disabled or
     *         not usable as configured
     */
    private RemoteCoordinatesResolver buildRemoteCoordinatesResolver() {
        if (remoteLookup == null || !remoteLookup.isEnabled()) {
            return null;
        }
        Credentials nexusCredentials = resolveCredentials(remoteLookup.getNexusServerId());
        Credentials artifactoryCredentials = resolveCredentials(remoteLookup.getArtifactoryServerId());
        return RemoteCoordinatesResolver.create(remoteLookup,
                nexusCredentials.username(), nexusCredentials.password(),
                artifactoryCredentials.username(), artifactoryCredentials.password())
                .orElse(null);
    }

    private record Credentials(String username, String password) {
        private static final Credentials NONE = new Credentials(null, null);
    }

    /**
     * Resolves and decrypts the username/password of a {@code settings.xml}
     * {@code <server>} entry.
     *
     * @param serverId the server id, or {@code null}/blank for anonymous access
     * @return the decrypted credentials, or {@link Credentials#NONE} if no
     *         server id is configured or no matching server is found
     */
    private Credentials resolveCredentials(String serverId) {
        if (serverId == null || serverId.isBlank()) {
            return Credentials.NONE;
        }
        Server server = session.getSettings().getServer(serverId);
        if (server == null) {
            getLog().warn("No <server> with id '" + serverId
                    + "' found in settings.xml; using anonymous access");
            return Credentials.NONE;
        }
        SettingsDecryptionResult result = settingsDecrypter.decrypt(
                new DefaultSettingsDecryptionRequest(server));
        Server decrypted = result.getServer() != null ? result.getServer() : server;
        return new Credentials(decrypted.getUsername(), decrypted.getPassword());
    }

    private List<FileEntry> collectDirectoryEntries(Path dir, MessageDigest digest) throws IOException {
        List<FileEntry> entries = new ArrayList<>();
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                String relativePath = dir.relativize(file).toString().replace('\\', '/');
                String hash = SbomUtils.computeHash(digest, file);
                entries.add(new FileEntry(
                        relativePath, hash, file.toFile()));
                return FileVisitResult.CONTINUE;
            }
        });
        return entries;
    }
}
