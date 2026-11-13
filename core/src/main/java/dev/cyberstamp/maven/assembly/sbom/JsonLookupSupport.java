package dev.cyberstamp.maven.assembly.sbom;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Extracts the fields the checksum-search backends need
 * ({@link MavenCentralCoordinatesLookup}, {@link NexusCoordinatesLookup},
 * {@link ArtifactoryCoordinatesLookup}) from their JSON responses: the
 * first object in a named array, and string fields within an object.
 *
 * <p>
 * Both lookups are by key name alone, found anywhere in the document (not
 * just at the top level) — e.g. Maven Central's Solr response nests
 * {@code docs} inside a {@code response} wrapper object, so each backend's
 * array/field name can be used directly without hardcoding its wrapper path.
 * </p>
 */
final class JsonLookupSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonLookupSupport() {
    }

    /**
     * Returns the first JSON object in the array value of {@code arrayKey},
     * serialized back to a JSON string, e.g. for
     * {@code {"docs":[{"a":1},{"a":2}]}} and {@code arrayKey="docs"},
     * returns {@code {"a":1}}.
     *
     * @param json the JSON document
     * @param arrayKey the key whose array value should be inspected
     * @return the first element, serialized as JSON, or empty if the key is
     *         absent, its value is not a non-empty array of objects, or the
     *         document is malformed
     */
    static Optional<String> firstArrayObject(String json, String arrayKey) {
        if (json == null) {
            return Optional.empty();
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            return Optional.empty();
        }
        if (root == null) {
            return Optional.empty();
        }
        JsonNode array = root.findPath(arrayKey);
        if (!array.isArray() || array.isEmpty()) {
            return Optional.empty();
        }
        JsonNode first = array.get(0);
        if (first == null || !first.isObject()) {
            return Optional.empty();
        }
        return Optional.of(first.toString());
    }

    /**
     * Returns the value of a string field within a JSON object fragment,
     * e.g. for {@code {"g":"org.example","a":"lib"}} and {@code key="a"},
     * returns {@code "lib"}.
     *
     * @param json a JSON object fragment
     * @param key the field name
     * @return the string value, or empty if absent, not a string, blank,
     *         or the document is malformed
     */
    static Optional<String> stringField(String json, String key) {
        if (json == null) {
            return Optional.empty();
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            return Optional.empty();
        }
        if (root == null) {
            return Optional.empty();
        }
        JsonNode value = root.findPath(key);
        if (!value.isTextual()) {
            return Optional.empty();
        }
        String text = value.textValue();
        return (text == null || text.isBlank()) ? Optional.empty() : Optional.of(text);
    }
}
