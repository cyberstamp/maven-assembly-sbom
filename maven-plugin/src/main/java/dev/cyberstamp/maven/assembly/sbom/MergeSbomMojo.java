package dev.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.util.List;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.model.Bom;

/**
 * Merges one or more CycloneDX BOMs into a base BOM and writes the result to a file.
 *
 * <p>
 * Components from each merge BOM are added to the base BOM either as top-level
 * components (flat merge) or nested under a parent component (nested merge).
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * <plugin>
 *   <groupId>dev.cyberstamp</groupId>
 *   <artifactId>cyclonedx-maven-plugin</artifactId>
 *   <executions>
 *     <execution>
 *       <goals>
 *         <goal>merge</goal>
 *       </goals>
 *       <configuration>
 *         <baseSbom>${project.build.directory}/base-bom.cdx.json</baseSbom>
 *         <externalSboms>
 *           <mergeBom>${project.build.directory}/extra-bom.cdx.json</mergeBom>
 *         </externalSboms>
 *       </configuration>
 *     </execution>
 *   </executions>
 * </plugin>
 * }</pre>
 */
@Mojo(name = "merge", defaultPhase = LifecyclePhase.PREPARE_PACKAGE)
public class MergeSbomMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true)
    private MavenProject project;

    @Component
    private MavenProjectHelper projectHelper;

    /**
     * Path to the base CycloneDX BOM file into which other BOMs will be merged.
     */
    @Parameter(required = true)
    private File baseSbom;

    /**
     * List of CycloneDX BOM files whose components will be merged into the base BOM.
     */
    @Parameter(required = true)
    private List<File> externalSboms;

    /**
     * Path where the merged BOM will be written.
     */
    @Parameter(defaultValue = "${project.build.directory}/merged-bom.cdx.json")
    private File outputFile;

    /**
     * Output format for the merged BOM. Supported values are {@code json} and {@code xml}.
     */
    @Parameter(defaultValue = "json")
    private String format;

    /**
     * Whether to pretty-print the output BOM.
     */
    @Parameter(defaultValue = "true")
    private boolean prettyPrint;

    /**
     * When {@code true}, components from the merge BOMs are added as nested sub-components of
     * a parent component rather than as top-level components. The parent is identified
     * by {@link #parentBomRef} or, if that is not set, by the {@code bom-ref} of the
     * base BOM's metadata component.
     */
    @Parameter(defaultValue = "false")
    private boolean nested;

    /**
     * The {@code bom-ref} of the component under which merged components should be
     * nested. Only used when {@link #nested} is {@code true}. If not specified, the
     * {@code bom-ref} of the base BOM's metadata component is used.
     */
    @Parameter
    private String parentBomRef;

    /**
     * Attaches the merged SBOM as a Maven project artifact with
     * type {@code cdx.json} or {@code cdx.xml} and classifier
     * {@code cyclonedx}.
     */
    @Parameter(defaultValue = "false")
    private boolean attach;

    /**
     * CycloneDX schema version to use for SBOM output, e.g. {@code "1.5"} or
     * {@code "1.6"}.
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

    @Override
    public void execute() throws MojoExecutionException {
        if (!baseSbom.isFile()) {
            throw new MojoExecutionException("Base BOM file does not exist: " + baseSbom);
        }

        Bom bom = BomReader.readBom(baseSbom);
        if (bom == null) {
            throw new MojoExecutionException("Failed to parse base BOM: " + baseSbom);
        }

        String parentRef = null;
        if (nested) {
            parentRef = parentBomRef;
            if (parentRef == null) {
                if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
                    parentRef = bom.getMetadata().getComponent().getBomRef();
                }
                if (parentRef == null) {
                    throw new MojoExecutionException(
                            "No parentBomRef configured and base BOM has no metadata component");
                }
            }
        }

        for (File file : externalSboms) {
            if (!file.isFile()) {
                throw new MojoExecutionException("Merge BOM file does not exist: " + file);
            }
            Bom external = BomReader.readBom(file);
            if (external == null) {
                throw new MojoExecutionException("Failed to parse merge BOM: " + file);
            }
            int componentCount = external.getComponents() != null ? external.getComponents().size() : 0;
            if (nested) {
                BomMerger.mergeUnder(bom, parentRef, external);
            } else {
                BomMerger.mergeFlat(bom, external);
            }
            getLog().info("Merged " + componentCount + " components from " + file.getName());
        }

        if (outputFile.getParentFile() != null) {
            outputFile.getParentFile().mkdirs();
        }
        try {
            BomWriter.write(bom, outputFile.toPath(), format, prettyPrint,
                    SchemaVersions.resolve(schemaVersion));
        } catch (java.io.IOException | GeneratorException e) {
            throw new MojoExecutionException("Failed to write merged BOM to " + outputFile, e);
        }

        getLog().info("Merged BOM written to " + outputFile);

        if (attach) {
            String type = "xml".equalsIgnoreCase(format) ? "cdx.xml" : "cdx.json";
            projectHelper.attachArtifact(project, type, "cyclonedx", outputFile);
            getLog().info("Attached merged SBOM artifact: type=" + type + ", classifier=cyclonedx");
        }
    }
}
