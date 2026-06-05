package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;

import org.junit.jupiter.api.Test;

class ArchiveContentTest {

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
