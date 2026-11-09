package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.List;

/**
 * User-configurable settings for identifying non-Maven-built archive entries
 * (e.g. jars built with Gradle or Ant) by resolving their Maven coordinates
 * from a remote package repository — Maven Central and/or an internal Nexus
 * or Artifactory instance — keyed by the entry's SHA-1 content hash.
 *
 * <p>
 * Disabled by default. When {@linkplain #isEnabled() enabled}, every backend
 * (Maven Central, Nexus, Artifactory) must also be opted into individually —
 * nothing is queried implicitly. If no {@linkplain #getIncludes() include}
 * glob pattern is configured, lookup defaults to {@code **&#47;*.jar} rather
 * than being skipped, so {@code enabled=true} alone is enough to try; set
 * {@link #setIncludes(List)} explicitly to narrow which unmatched files
 * trigger a network call. The lookup only ever runs for archive entries that
 * remain unidentified after every other (local, offline) identification
 * technique.
 * </p>
 */
public class RemoteArtifactLookup {

    private boolean enabled;
    private List<String> includes;
    private List<String> excludes;
    private boolean central = false;
    private String nexusUrl;
    private String nexusServerId;
    private String artifactoryUrl;
    private String artifactoryServerId;
    private int timeoutMillis = 3000;
    private int maxLookups = 200;

    /**
     * Returns whether remote Maven coordinates lookup is enabled.
     *
     * @return {@code true} if enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables or disables remote Maven coordinates lookup.
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
     * Sets the include glob patterns. When {@link #isEnabled()} is
     * {@code true} and this is left unset (or empty), lookup defaults to
     * {@code **&#47;*.jar}. Set this explicitly to narrow the subset of
     * unmatched files that can trigger a network call.
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
     * Enables or disables querying the public Maven Central search API.
     * Disabled by default: enabling {@link #setEnabled(boolean) remoteLookup}
     * does not by itself send any artifact checksum to a public, third-party
     * service — each backend, including Central, must be opted into
     * individually.
     *
     * @param central whether to query Maven Central
     */
    public void setCentral(boolean central) {
        this.central = central;
    }

    /**
     * Returns the complete Nexus Repository Manager 3 search URL to query,
     * containing a {@code {sha1}} placeholder, or {@code null} if Nexus
     * lookup is disabled.
     *
     * @return the Nexus search URL, or {@code null}
     */
    public String getNexusUrl() {
        return nexusUrl;
    }

    /**
     * Sets the complete search URL of a Nexus Repository Manager 3 instance,
     * with a literal {@code {sha1}} in place of the content hash, e.g.
     * {@code https://nexus.example.com/service/rest/v1/search?sha1={sha1}}.
     * Setting this enables Nexus lookup; {@code {sha1}} is substituted with
     * the actual hash and the rest of the URL is used exactly as given.
     *
     * <p>
     * This is a full URL rather than just a server address so you can add
     * Nexus's own search parameters — e.g. its {@code repository} filter, to
     * restrict the search to one repository:
     * {@code https://nexus.example.com/service/rest/v1/search?sha1={sha1}&repository=my-repo}.
     * It also means that if Nexus ever changes its REST API path, only this
     * setting needs updating, not the plugin itself.
     * </p>
     *
     * <p>
     * If the given value does not contain {@code {sha1}}, Nexus lookup is
     * skipped with a warning — there is no default path to fall back to.
     * </p>
     *
     * @param nexusUrl the complete Nexus search URL, containing a
     *        {@code {sha1}} placeholder
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
     * Returns the complete Artifactory search URL to query, containing a
     * {@code {sha1}} placeholder, or {@code null} if Artifactory lookup is
     * disabled.
     *
     * @return the Artifactory search URL, or {@code null}
     */
    public String getArtifactoryUrl() {
        return artifactoryUrl;
    }

    /**
     * Sets the complete checksum search URL of an Artifactory instance, with
     * a literal {@code {sha1}} in place of the content hash, e.g.
     * {@code https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}}.
     * Setting this enables Artifactory lookup; {@code {sha1}} is substituted
     * with the actual hash and the rest of the URL is used exactly as given.
     *
     * <p>
     * This is a full URL rather than just a server address so you can add
     * Artifactory's own search parameters — e.g. its {@code repos} filter, to
     * restrict the search to specific repositories:
     * {@code https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}&repos=central,my-internal-repo}.
     * It also means that if Artifactory ever changes its REST API path, only
     * this setting needs updating, not the plugin itself.
     * </p>
     *
     * <p>
     * If the given value does not contain {@code {sha1}}, Artifactory lookup
     * is skipped with a warning — there is no default path to fall back to.
     * </p>
     *
     * @param artifactoryUrl the complete Artifactory search URL, containing
     *        a {@code {sha1}} placeholder
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
