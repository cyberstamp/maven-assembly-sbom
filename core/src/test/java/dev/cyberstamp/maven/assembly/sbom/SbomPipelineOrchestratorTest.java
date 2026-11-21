package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.component.evidence.Method;
import org.junit.jupiter.api.Test;

class SbomPipelineOrchestratorTest {

    private static AssemblyComponents model(PackageComponent... comps) {
        AssemblyComponents m = new AssemblyComponents();
        AssemblyMetadata md = new AssemblyMetadata();
        md.setProjectGroupId("g");
        md.setProjectArtifactId("a");
        md.setProjectVersion("1");
        md.setHashAlgorithmSpec("SHA-256");
        m.setMetadata(md);
        for (PackageComponent c : comps) {
            m.addComponent(c);
        }
        return m;
    }

    @Test
    void enrichRunsLicenseSourceWhenProvided() {
        LicenseSource src = (g, a, v) -> List.of(new RawLicense("Apache License 2.0", null));
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null));
        SbomPipeline.forModel(m).licenseSource(src).enrich();
        PackageComponent pc = (PackageComponent) m.components().get(0);
        assertEquals("Apache-2.0", pc.licenses().get(0).spdxId());
    }

    @Test
    void enrichSkipsLicensesWhenNoSource() {
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null));
        SbomPipeline.forModel(m).enrich();
        assertTrue(((PackageComponent) m.components().get(0)).licenses().isEmpty());
    }

    @Test
    void renderProducesBom() {
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null));
        Bom bom = SbomPipeline.forModel(m).render();
        assertNotNull(bom.getComponents());
        assertFalse(bom.getComponents().isEmpty());
    }

    /**
     * The option governs this library's own findings; an identification a
     * producer put on the model passes through untouched.
     */
    @Test
    void identityEvidenceFalseKeepsProducerIdentification() {
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), "lib/a.jar", null,
                true, new Identification(Technique.ATTESTATION, 0.9)));
        Bom bom = SbomPipeline.forModel(m).identityEvidence(false).render();
        var identity = bom.getComponents().get(0).getEvidence().getIdentities().get(0);
        assertEquals(0.9, identity.getConfidence());
        assertEquals(Method.Technique.ATTESTATION,
                identity.getMethods().get(0).getTechnique());
    }

    @Test
    void identityEvidenceSurvivesLicenseEnrichment() {
        LicenseSource src = (g, a, v) -> List.of(new RawLicense("Apache License 2.0", null));
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), "lib/a.jar", null,
                true, Identification.hashMatch()));
        Bom bom = SbomPipeline.forModel(m).licenseSource(src).render();
        var component = bom.getComponents().get(0);
        assertNotNull(component.getLicenses(), "license enrichment ran");
        assertEquals(1.0, component.getEvidence().getIdentities().get(0).getConfidence());
    }

    @Test
    void renderMakesBomRefsUniqueAndKeepsUnknownDependenciesUndeclared() {
        // x ships top-level and bundled in a shaded jar (dependencies unknown)
        ArtifactCoords x = ArtifactCoords.of("g", "x", "1");
        PackageComponent bundled = new PackageComponent(x, null, null, List.of(), List.of(), false);
        AssemblyComponents m = model(
                new PackageComponent(ArtifactCoords.of("g", "shaded", "1"), "lib/shaded.jar", "aaa", List.of(),
                        List.of(bundled)),
                new PackageComponent(x, "lib/x.jar", "bbb", List.of(), List.of()));

        Bom bom = SbomPipeline.forModel(m).render();

        Component shaded = bom.getComponents().stream()
                .filter(c -> "shaded".equals(c.getName())).findFirst().orElseThrow();
        assertEquals("pkg:maven/g/x@1#2", shaded.getComponents().get(0).getBomRef());
        List<String> refs = bom.getDependencies().stream().map(Dependency::getRef).toList();
        assertTrue(refs.contains("pkg:maven/g/x@1"), "the top-level x is a leaf");
        assertFalse(refs.contains("pkg:maven/g/x@1#2"), "the bundled copy's dependencies are unknown");
        assertEquals(refs.stream().sorted().toList(), refs, "entries are sorted");
    }
}
