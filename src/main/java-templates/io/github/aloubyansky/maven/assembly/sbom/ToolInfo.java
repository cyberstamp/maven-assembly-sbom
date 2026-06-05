package io.github.aloubyansky.maven.assembly.sbom;

final class ToolInfo {
    static final String GROUP_ID = "${project.groupId}";
    static final String ARTIFACT_ID = "${project.artifactId}";
    static final String VERSION = "${project.version}";

    private ToolInfo() {
    }
}
