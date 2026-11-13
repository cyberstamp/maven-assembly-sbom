package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class JsonLookupSupportTest {

    @Test
    void extractsFirstArrayObjectFromCentralStyleResponse() {
        String json = "{\"responseHeader\":{\"status\":0},\"response\":{\"numFound\":1,\"start\":0,"
                + "\"docs\":[{\"id\":\"org.example:lib:1.0\",\"g\":\"org.example\",\"a\":\"lib\",\"v\":\"1.0\","
                + "\"p\":\"jar\"}]}}";
        Optional<String> doc = JsonLookupSupport.firstArrayObject(json, "docs");
        assertTrue(doc.isPresent());
        assertEquals(Optional.of("org.example"), JsonLookupSupport.stringField(doc.get(), "g"));
        assertEquals(Optional.of("lib"), JsonLookupSupport.stringField(doc.get(), "a"));
        assertEquals(Optional.of("1.0"), JsonLookupSupport.stringField(doc.get(), "v"));
    }

    @Test
    void extractsFirstArrayObjectWithNestedObjectsLikeNexusItems() {
        String json = "{\"items\":[{\"id\":\"xyz\",\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\","
                + "\"assets\":[{\"downloadUrl\":\"https://x/y.jar\",\"checksum\":{\"sha1\":\"abc\"}}]},"
                + "{\"group\":\"other\",\"name\":\"other-lib\",\"version\":\"9.9\"}],\"continuationToken\":null}";
        Optional<String> item = JsonLookupSupport.firstArrayObject(json, "items");
        assertTrue(item.isPresent());
        assertEquals(Optional.of("com.example"), JsonLookupSupport.stringField(item.get(), "group"));
        assertEquals(Optional.of("lib"), JsonLookupSupport.stringField(item.get(), "name"));
        assertEquals(Optional.of("2.0"), JsonLookupSupport.stringField(item.get(), "version"));
    }

    @Test
    void extractsStringFieldWithEscapedQuote() {
        String json = "{\"uri\":\"https://example.com/path/with\\\"quote/file.jar\"}";
        assertEquals(Optional.of("https://example.com/path/with\"quote/file.jar"),
                JsonLookupSupport.stringField(json, "uri"));
    }

    @Test
    void returnsEmptyForMissingArrayKey() {
        assertTrue(JsonLookupSupport.firstArrayObject("{\"other\":[]}", "docs").isEmpty());
    }

    @Test
    void returnsEmptyForEmptyArray() {
        assertTrue(JsonLookupSupport.firstArrayObject("{\"docs\":[]}", "docs").isEmpty());
    }

    @Test
    void returnsEmptyForMissingStringField() {
        assertTrue(JsonLookupSupport.stringField("{\"g\":\"org.example\"}", "a").isEmpty());
    }

    @Test
    void returnsEmptyForBlankStringField() {
        assertTrue(JsonLookupSupport.stringField("{\"g\":\"\"}", "g").isEmpty());
    }

    @Test
    void doesNotMatchKeySubstringOfAnotherKey() {
        // "g" must not match inside "group" or "gav"
        String json = "{\"group\":\"wrong\",\"g\":\"right\"}";
        assertEquals(Optional.of("right"), JsonLookupSupport.stringField(json, "g"));
    }
}
