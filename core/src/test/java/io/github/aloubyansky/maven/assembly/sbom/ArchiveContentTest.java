package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.Dependency;
import org.junit.jupiter.api.Test;

class ArchiveContentTest {

    @Test
    void detectedSbomsInitiallyEmpty() {
        ArchiveContent content = new ArchiveContent();
        assertTrue(content.detectedSboms().isEmpty());
    }

    @Test
    void addAndRetrieveDetectedSboms() {
        ArchiveContent content = new ArchiveContent();

        Bom bom1 = new Bom();
        Component comp1 = new Component();
        comp1.setName("lib-a");
        bom1.addComponent(comp1);
        ArtifactCoords parent1 = ArtifactCoords.of("org.a", "parent", "1.0");
        content.addDetectedSbom(new ArchiveContent.DetectedSbom(
                "lib/parent-1.0.jar/META-INF/sbom/bom.cdx.json", bom1, parent1));

        Bom bom2 = new Bom();
        Component comp2 = new Component();
        comp2.setName("lib-b");
        bom2.addComponent(comp2);
        content.addDetectedSbom(new ArchiveContent.DetectedSbom(
                "META-INF/sbom/bom.cdx.json", bom2, null));

        List<ArchiveContent.DetectedSbom> sboms = content.detectedSboms();
        assertEquals(2, sboms.size());
        assertEquals("lib-a", sboms.get(0).parsedBom().getComponents().get(0).getName());
        assertEquals(parent1, sboms.get(0).parentArtifact());
        assertNull(sboms.get(1).parentArtifact());
    }

    @Test
    void nestedDepsByParentTracksPerParent() {
        ArchiveContent content = new ArchiveContent();

        ArtifactCoords parent1 = ArtifactCoords.of("org.a", "war-a", "1.0");
        ArtifactCoords parent2 = ArtifactCoords.of("org.b", "war-b", "2.0");

        Dependency dep1 = new Dependency(
                new DefaultArtifact("org.x", "child-1", "jar", "1.0"), "compile");
        Dependency dep2 = new Dependency(
                new DefaultArtifact("org.y", "child-2", "jar", "1.0"), "compile");
        Dependency dep3 = new Dependency(
                new DefaultArtifact("org.z", "child-3", "jar", "1.0"), "compile");

        content.addNestedDependency(parent1, dep1);
        content.addNestedDependency(parent1, dep2);
        content.addNestedDependency(parent2, dep3);

        Map<ArtifactCoords, List<Dependency>> map = content.nestedDepsByParent();
        assertEquals(2, map.size());
        assertEquals(2, map.get(parent1).size());
        assertEquals(1, map.get(parent2).size());
        assertEquals("child-1", map.get(parent1).get(0).getArtifact().getArtifactId());
        assertEquals("child-3", map.get(parent2).get(0).getArtifact().getArtifactId());
    }

    @Test
    void collectKnownArtifactCoordsIncludesAllSources() {
        ArchiveContent content = new ArchiveContent();

        ArtifactCoords topLevel = ArtifactCoords.of("org.a", "top", "1.0");
        ArtifactCoords nested = ArtifactCoords.of("org.b", "nested", "2.0");
        ArtifactCoords fileNested = ArtifactCoords.of("org.c", "file-nested", "3.0");

        content.addMavenEntry(new ArchiveContent.MavenEntry(topLevel, "lib/top-1.0.jar", "h1"));
        content.addNestedEntry(new ArchiveContent.NestedMavenEntry(topLevel, nested, "lib/nested-2.0.jar", "h2"));
        content.addFileNestedArtifact("lib/shaded.jar", fileNested);

        Set<ArtifactCoords> known = content.collectKnownArtifactCoords();

        assertEquals(3, known.size());
        assertTrue(known.contains(topLevel));
        assertTrue(known.contains(nested));
        assertTrue(known.contains(fileNested),
                "file-nested artifacts must be included for dependency graph filtering");
    }
}
