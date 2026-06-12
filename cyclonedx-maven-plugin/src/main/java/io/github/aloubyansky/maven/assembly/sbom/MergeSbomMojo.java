package io.github.aloubyansky.maven.assembly.sbom;

import java.io.File;
import java.util.List;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
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
 *   <groupId>io.github.aloubyansky</groupId>
 *   <artifactId>cyclonedx-maven-plugin</artifactId>
 *   <executions>
 *     <execution>
 *       <goals>
 *         <goal>merge-sbom</goal>
 *       </goals>
 *       <configuration>
 *         <baseBom>${project.build.directory}/base-bom.cdx.json</baseBom>
 *         <mergeBoms>
 *           <mergeBom>${project.build.directory}/extra-bom.cdx.json</mergeBom>
 *         </mergeBoms>
 *       </configuration>
 *     </execution>
 *   </executions>
 * </plugin>
 * }</pre>
 */
@Mojo(name = "merge-sbom", defaultPhase = LifecyclePhase.PREPARE_PACKAGE)
public class MergeSbomMojo extends AbstractMojo {

    /**
     * Path to the base CycloneDX BOM file into which other BOMs will be merged.
     */
    @Parameter(required = true)
    private File baseBom;

    /**
     * List of CycloneDX BOM files whose components will be merged into the base BOM.
     */
    @Parameter(required = true)
    private List<File> mergeBoms;

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
     * When {@code true}, components from the merge BOMs are added as dependencies of
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

    @Override
    public void execute() throws MojoExecutionException {
        if (!baseBom.isFile()) {
            throw new MojoExecutionException("Base BOM file does not exist: " + baseBom);
        }

        Bom bom = BomReader.readBom(baseBom);
        if (bom == null) {
            throw new MojoExecutionException("Failed to parse base BOM: " + baseBom);
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

        for (File file : mergeBoms) {
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
            BomWriter.write(bom, outputFile.toPath(), format, prettyPrint);
        } catch (java.io.IOException | GeneratorException e) {
            throw new MojoExecutionException("Failed to write merged BOM to " + outputFile, e);
        }

        getLog().info("Merged BOM written to " + outputFile);
    }
}
