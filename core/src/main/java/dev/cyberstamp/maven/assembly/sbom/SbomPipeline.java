package dev.cyberstamp.maven.assembly.sbom;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;

/**
 * Runs the standard SBOM enrichment transforms over an {@link AssemblyComponents}
 * model and renders it, driven by pluggable data providers. This is the
 * out-of-the-box entry point every producer uses instead of orchestrating
 * transforms by hand: supply the providers you can, and the corresponding
 * transform runs.
 *
 * <ul>
 * <li>a {@link ShadedJarDetection.JarLocator} enables shaded-artifact
 * detection;</li>
 * <li>a {@link LicenseSource} enables license enrichment.</li>
 * </ul>
 *
 * <p>
 * Shaded detection runs before license enrichment so that newly-nested bundled
 * artifacts are also license-resolved.
 * </p>
 */
public final class SbomPipeline {

    private final AssemblyComponents model;
    private ShadedJarDetection.JarLocator jarLocator;
    private LicenseSource licenseSource;
    private boolean failOnMissingLicense;
    private boolean identityEvidence = true;

    private SbomPipeline(AssemblyComponents model) {
        this.model = model;
    }

    /**
     * Starts a pipeline for the given model.
     *
     * @param model the model to enrich and render
     * @return a new pipeline
     */
    public static SbomPipeline forModel(AssemblyComponents model) {
        return new SbomPipeline(model);
    }

    /**
     * Enables shaded-artifact detection using the given JAR locator.
     *
     * @param locator locates a component's artifact, or {@code null} to skip
     *        shaded detection
     * @return this pipeline
     */
    public SbomPipeline jarLocator(ShadedJarDetection.JarLocator locator) {
        this.jarLocator = locator;
        return this;
    }

    /**
     * Enables license enrichment using the given source.
     *
     * @param source supplies raw POM licenses, or {@code null} to skip license
     *        enrichment
     * @return this pipeline
     */
    public SbomPipeline licenseSource(LicenseSource source) {
        this.licenseSource = source;
        return this;
    }

    /**
     * Sets the missing-license policy for license enrichment.
     *
     * @param fail whether to fail on artifacts with no license information
     * @return this pipeline
     */
    public SbomPipeline failOnMissingLicense(boolean fail) {
        this.failOnMissingLicense = fail;
        return this;
    }

    /**
     * Sets whether this library's own transforms (shaded detection) record an
     * {@link Identification} on the components they add. Identification a
     * producer put on the model is rendered either way. Defaults to
     * {@code true}.
     *
     * @param enabled whether to emit identity evidence
     * @return this pipeline
     */
    public SbomPipeline identityEvidence(boolean enabled) {
        this.identityEvidence = enabled;
        return this;
    }

    /**
     * Runs the enabled transforms over the model in the standard order
     * (shaded detection, then license enrichment) and returns it.
     *
     * @return the enriched model
     */
    public AssemblyComponents enrich() {
        if (jarLocator != null) {
            new ShadedJarDetection(jarLocator, identityEvidence).apply(model);
        }
        if (licenseSource != null) {
            new LicenseEnrichment(licenseSource, failOnMissingLicense).apply(model);
        }
        return model;
    }

    /**
     * {@link #enrich() Enriches} the model, then renders it to a CycloneDX BOM
     * with unique component bom-refs and sorted dependency entries. Several
     * copies of an artifact (e.g. shipped at the top level and bundled in a
     * shaded jar) are separate components: one keeps the artifact's bom-ref,
     * the others get {@code #2}, {@code #3}, ... appended.
     *
     * @return the rendered BOM
     */
    public Bom render() {
        enrich();
        Set<Component> dependenciesUnknown = Collections.newSetFromMap(new IdentityHashMap<>());
        Bom bom = new BomRenderer().render(model, dependenciesUnknown);
        BomFinalizer.deduplicateBomRefs(bom, dependenciesUnknown);
        BomFinalizer.sortDependencies(bom);
        return bom;
    }
}
