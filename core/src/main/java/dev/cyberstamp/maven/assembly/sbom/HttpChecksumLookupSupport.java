package dev.cyberstamp.maven.assembly.sbom;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared HTTP GET helper for the checksum-search lookup implementations.
 * Centralizes timeout handling, optional Basic authentication, and the
 * "never throw, just log and report empty" contract required by
 * {@link ChecksumArtifactLookup}.
 */
final class HttpChecksumLookupSupport {

    private static final Logger log = LoggerFactory.getLogger(HttpChecksumLookupSupport.class);

    private HttpChecksumLookupSupport() {
    }

    /**
     * Performs a GET request and returns the response body, or empty if the
     * request failed, timed out, or did not return HTTP 200.
     *
     * @param client the shared HTTP client
     * @param uri the request URI
     * @param timeout the per-request timeout
     * @param basicAuthHeader a pre-built {@code Authorization: Basic ...}
     *        header value, or {@code null} for an unauthenticated request
     * @return the response body, or empty
     */
    static Optional<String> get(HttpClient client, URI uri, Duration timeout, String basicAuthHeader) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .GET();
            if (basicAuthHeader != null) {
                builder.header("Authorization", basicAuthHeader);
            }
            HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.debug("Checksum lookup against {} returned HTTP {}", uri, response.statusCode());
                return Optional.empty();
            }
            return Optional.of(response.body());
        } catch (IOException e) {
            log.debug("Checksum lookup against {} failed", uri, e);
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (RuntimeException e) {
            log.debug("Checksum lookup against {} failed", uri, e);
            return Optional.empty();
        }
    }

    /**
     * Builds an {@code Authorization: Basic ...} header value.
     *
     * @param username the username
     * @param password the password
     * @return the header value
     */
    static String basicAuthHeader(String username, String password) {
        String token = username + ":" + password;
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
