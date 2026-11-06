package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.List;

/**
 * User-configurable settings for identifying non-Maven-built archive entries
 * (e.g. jars built with Gradle or Ant) by looking up their SHA-1 checksum
 * against Maven Central and/or an internal Nexus or Artifactory instance.
 *
 * <p>
 * Disabled by default. When {@linkplain #isEnabled() enabled}, at least one
 * {@linkplain #getIncludes() include} glob pattern is required so that only a
 * bounded, intentional subset of unmatched files triggers a network call.
 * The lookup only ever runs for archive entries that remain unidentified
 * after every other (local, offline) identification technique.
 * </p>
 */
public class RemoteArtifactLookup {

    private boolean enabled;
    private List<String> includes;
    private List<String> excludes;
    private boolean central = true;
    private String nexusUrl;
    private String nexusServerId;
    private String artifactoryUrl;
    private String artifactoryServerId;
    private int timeoutMillis = 3000;
    private int maxLookups = 200;

    /**
     * Returns whether remote checksum lookup is enabled.
     *
     * @return {@code true} if enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables or disables remote checksum lookup.
     *
     * @param enabled whether to enable the lookup
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Returns the glob patterns (matched against the archive-relative path)
     * that select which unmatched files are eligible for remote lookup.
     *
     * @return the include patterns, or {@code null} if unset
     */
    public List<String> getIncludes() {
        return includes;
    }

    /**
     * Sets the include glob patterns. Required (non-empty) when
     * {@link #isEnabled()} is {@code true}; otherwise no files are looked up.
     *
     * @param includes the include patterns
     */
    public void setIncludes(List<String> includes) {
        this.includes = includes;
    }

    /**
     * Returns the glob patterns that exclude otherwise-matching files from
     * remote lookup.
     *
     * @return the exclude patterns, or {@code null} if unset
     */
    public List<String> getExcludes() {
        return excludes;
    }

    /**
     * Sets the exclude glob patterns.
     *
     * @param excludes the exclude patterns
     */
    public void setExcludes(List<String> excludes) {
        this.excludes = excludes;
    }

    /**
     * Returns whether Maven Central ({@code search.maven.org}) is queried.
     *
     * @return {@code true} if Maven Central lookup is enabled
     */
    public boolean isCentral() {
        return central;
    }

    /**
     * Enables or disables querying Maven Central. Enabled by default since it
     * requires no configuration and covers most publicly-available artifacts.
     *
     * @param central whether to query Maven Central
     */
    public void setCentral(boolean central) {
        this.central = central;
    }

    /**
     * Returns the base URL of an internal Nexus Repository Manager 3 instance
     * to query, or {@code null} if Nexus lookup is disabled.
     *
     * @return the Nexus base URL, or {@code null}
     */
    public String getNexusUrl() {
        return nexusUrl;
    }

    /**
     * Sets the base URL of a Nexus Repository Manager 3 instance (e.g.
     * {@code https://nexus.example.com}). Setting this enables Nexus lookup.
     *
     * @param nexusUrl the Nexus base URL
     */
    public void setNexusUrl(String nexusUrl) {
        this.nexusUrl = nexusUrl;
    }

    /**
     * Returns the {@code settings.xml} {@code <server>} id whose credentials
     * are used for Basic authentication against Nexus, or {@code null} for
     * anonymous access.
     *
     * @return the server id, or {@code null}
     */
    public String getNexusServerId() {
        return nexusServerId;
    }

    /**
     * Sets the {@code settings.xml} {@code <server>} id for Nexus credentials.
     *
     * @param nexusServerId the server id
     */
    public void setNexusServerId(String nexusServerId) {
        this.nexusServerId = nexusServerId;
    }

    /**
     * Returns the base URL of an internal Artifactory instance to query, or
     * {@code null} if Artifactory lookup is disabled.
     *
     * @return the Artifactory base URL, or {@code null}
     */
    public String getArtifactoryUrl() {
        return artifactoryUrl;
    }

    /**
     * Sets the base URL of an Artifactory instance (e.g.
     * {@code https://artifactory.example.com/artifactory}). Setting this
     * enables Artifactory lookup.
     *
     * @param artifactoryUrl the Artifactory base URL
     */
    public void setArtifactoryUrl(String artifactoryUrl) {
        this.artifactoryUrl = artifactoryUrl;
    }

    /**
     * Returns the {@code settings.xml} {@code <server>} id whose credentials
     * are used for Basic authentication against Artifactory, or {@code null}
     * for anonymous access.
     *
     * @return the server id, or {@code null}
     */
    public String getArtifactoryServerId() {
        return artifactoryServerId;
    }

    /**
     * Sets the {@code settings.xml} {@code <server>} id for Artifactory
     * credentials.
     *
     * @param artifactoryServerId the server id
     */
    public void setArtifactoryServerId(String artifactoryServerId) {
        this.artifactoryServerId = artifactoryServerId;
    }

    /**
     * Returns the per-request connect/response timeout, in milliseconds.
     *
     * @return the timeout in milliseconds
     */
    public int getTimeoutMillis() {
        return timeoutMillis;
    }

    /**
     * Sets the per-request connect/response timeout, in milliseconds.
     *
     * @param timeoutMillis the timeout in milliseconds
     */
    public void setTimeoutMillis(int timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    /**
     * Returns the maximum number of remote lookup HTTP calls performed during
     * a single SBOM generation run, regardless of how many files match the
     * configured glob patterns. A safety net in addition to the glob filter.
     *
     * @return the maximum number of lookups
     */
    public int getMaxLookups() {
        return maxLookups;
    }

    /**
     * Sets the maximum number of remote lookup HTTP calls per run.
     *
     * @param maxLookups the maximum number of lookups
     */
    public void setMaxLookups(int maxLookups) {
        this.maxLookups = maxLookups;
    }

    /**
     * Returns a defensive, non-null copy of {@link #getIncludes()}.
     *
     * @return the include patterns, never {@code null}
     */
    List<String> includesOrEmpty() {
        return includes == null ? List.of() : new ArrayList<>(includes);
    }

    /**
     * Returns a defensive, non-null copy of {@link #getExcludes()}.
     *
     * @return the exclude patterns, never {@code null}
     */
    List<String> excludesOrEmpty() {
        return excludes == null ? List.of() : new ArrayList<>(excludes);
    }
}
