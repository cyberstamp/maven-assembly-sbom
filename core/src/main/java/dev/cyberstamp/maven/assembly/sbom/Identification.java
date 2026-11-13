package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

/**
 * How a {@link PackageComponent}'s identity was determined, rendered as its
 * CycloneDX identity evidence.
 *
 * <p>
 * The factories cover the cases this library produces itself. Producers
 * building the model directly may construct any {@link Technique} and
 * confidence that describes how they identified a component. A component
 * with no identification (a {@code null} {@link PackageComponent#identification()})
 * gets no identity evidence.
 * </p>
 *
 * @param technique how the identity was determined; never {@code null}
 * @param confidence the confidence in the identity, in {@code [0, 1]}
 */
public record Identification(Technique technique, double confidence) {

    /**
     * Requires a non-null technique and a confidence in {@code [0, 1]}.
     */
    public Identification {
        Objects.requireNonNull(technique, "technique");
        if (Double.isNaN(confidence) || confidence < 0.0 || confidence > 1.0) {
            throw new IllegalArgumentException("confidence must be in [0, 1], got: " + confidence);
        }
    }

    /**
     * The archive entry's content hash matched a resolved artifact.
     *
     * @return {@code hash-comparison} at full confidence
     */
    public static Identification hashMatch() {
        return new Identification(Technique.HASH_COMPARISON, 1.0);
    }

    /**
     * An unpacked artifact matched on a subset of its member files rather
     * than on the artifact itself.
     *
     * @return {@code hash-comparison} at reduced confidence
     */
    public static Identification unpackedContentMatch() {
        return new Identification(Technique.HASH_COMPARISON, 0.8);
    }

    /**
     * Coordinates read verbatim from the component's own {@code pom.properties}.
     *
     * @return {@code manifest-analysis} at full confidence
     */
    public static Identification pomProperties() {
        return new Identification(Technique.MANIFEST_ANALYSIS, 1.0);
    }

    /**
     * Coordinates read from {@code pom.properties}, where a filename heuristic
     * chose which of a shaded jar's descriptors is the jar itself.
     *
     * @return {@code manifest-analysis} at reduced confidence
     */
    public static Identification pomPropertiesFilenameOwner() {
        return new Identification(Technique.MANIFEST_ANALYSIS, 0.5);
    }

    /**
     * The component's content hash was correlated against a remote package
     * repository (e.g. Maven Central, Nexus, Artifactory) rather than an
     * artifact resolved as part of this build.
     *
     * @return {@code hash-comparison} at reduced confidence
     */
    public static Identification remoteCoordinatesLookup() {
        return new Identification(Technique.HASH_COMPARISON, 0.9);
    }
}
