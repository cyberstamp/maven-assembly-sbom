package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class MinimalJsonTest {

    @Test
    void extractsFirstArrayObjectFromCentralStyleResponse() {
        String json = "{\"responseHeader\":{\"status\":0},\"response\":{\"numFound\":1,\"start\":0,"
                + "\"docs\":[{\"id\":\"org.example:lib:1.0\",\"g\":\"org.example\",\"a\":\"lib\",\"v\":\"1.0\","
                + "\"p\":\"jar\"}]}}";
        Optional<String> doc = MinimalJson.firstArrayObject(json, "docs");
        assertTrue(doc.isPresent());
        assertEquals(Optional.of("org.example"), MinimalJson.stringField(doc.get(), "g"));
        assertEquals(Optional.of("lib"), MinimalJson.stringField(doc.get(), "a"));
        assertEquals(Optional.of("1.0"), MinimalJson.stringField(doc.get(), "v"));
    }

    @Test
    void extractsFirstArrayObjectWithNestedObjectsLikeNexusItems() {
        String json = "{\"items\":[{\"id\":\"xyz\",\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\","
                + "\"assets\":[{\"downloadUrl\":\"https://x/y.jar\",\"checksum\":{\"sha1\":\"abc\"}}]},"
                + "{\"group\":\"other\",\"name\":\"other-lib\",\"version\":\"9.9\"}],\"continuationToken\":null}";
        Optional<String> item = MinimalJson.firstArrayObject(json, "items");
        assertTrue(item.isPresent());
        assertEquals(Optional.of("com.example"), MinimalJson.stringField(item.get(), "group"));
        assertEquals(Optional.of("lib"), MinimalJson.stringField(item.get(), "name"));
        assertEquals(Optional.of("2.0"), MinimalJson.stringField(item.get(), "version"));
    }

    @Test
    void extractsStringFieldWithEscapedQuote() {
        String json = "{\"uri\":\"https://example.com/path/with\\\"quote/file.jar\"}";
        assertEquals(Optional.of("https://example.com/path/with\"quote/file.jar"),
                MinimalJson.stringField(json, "uri"));
    }

    @Test
    void returnsEmptyForMissingArrayKey() {
        assertTrue(MinimalJson.firstArrayObject("{\"other\":[]}", "docs").isEmpty());
    }

    @Test
    void returnsEmptyForEmptyArray() {
        assertTrue(MinimalJson.firstArrayObject("{\"docs\":[]}", "docs").isEmpty());
    }

    @Test
    void returnsEmptyForMissingStringField() {
        assertTrue(MinimalJson.stringField("{\"g\":\"org.example\"}", "a").isEmpty());
    }

    @Test
    void returnsEmptyForBlankStringField() {
        assertTrue(MinimalJson.stringField("{\"g\":\"\"}", "g").isEmpty());
    }

    @Test
    void doesNotMatchKeySubstringOfAnotherKey() {
        // "g" must not match inside "group" or "gav"
        String json = "{\"group\":\"wrong\",\"g\":\"right\"}";
        assertEquals(Optional.of("right"), MinimalJson.stringField(json, "g"));
    }
}
