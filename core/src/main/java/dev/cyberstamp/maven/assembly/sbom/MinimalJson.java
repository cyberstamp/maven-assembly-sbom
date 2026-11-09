package dev.cyberstamp.maven.assembly.sbom;

import java.util.Optional;

/**
 * Minimal, dependency-free helpers for pulling a handful of known scalar
 * fields out of the small, fixed-shape JSON responses returned by the
 * checksum-search APIs ({@link MavenCentralCoordinatesLookup},
 * {@link NexusCoordinatesLookup}, {@link ArtifactoryCoordinatesLookup}).
 *
 * <p>
 * This is intentionally not a general-purpose JSON parser: it only needs to
 * extract the first object of a named array, and string-valued fields from
 * within an object, which is sufficient for the documents these APIs return.
 * Pulling in a JSON library for this would be a disproportionate dependency
 * for three small, well-known response shapes.
 * </p>
 */
final class MinimalJson {

    private MinimalJson() {
    }

    /**
     * Returns the substring of the first JSON object inside the array value
     * of {@code arrayKey}, e.g. for {@code {"docs":[{"a":1},{"a":2}]}} and
     * {@code arrayKey="docs"}, returns {@code {"a":1}}.
     *
     * @param json the JSON document
     * @param arrayKey the key whose array value should be inspected
     * @return the first element's object source, or empty if the key is
     *         absent, its value is not a non-empty array of objects, or the
     *         document is malformed
     */
    static Optional<String> firstArrayObject(String json, String arrayKey) {
        if (json == null) {
            return Optional.empty();
        }
        int keyIdx = indexOfKey(json, arrayKey);
        if (keyIdx < 0) {
            return Optional.empty();
        }
        int colon = json.indexOf(':', keyIdx);
        if (colon < 0) {
            return Optional.empty();
        }
        int bracket = skipWhitespace(json, colon + 1);
        if (bracket >= json.length() || json.charAt(bracket) != '[') {
            return Optional.empty();
        }
        int objStart = skipWhitespace(json, bracket + 1);
        if (objStart >= json.length() || json.charAt(objStart) != '{') {
            return Optional.empty();
        }
        int objEnd = matchBalanced(json, objStart, '{', '}');
        if (objEnd < 0) {
            return Optional.empty();
        }
        return Optional.of(json.substring(objStart, objEnd + 1));
    }

    /**
     * Returns the decoded value of a string-valued field within a JSON
     * object fragment, e.g. for {@code {"g":"org.example","a":"lib"}} and
     * {@code key="a"}, returns {@code "lib"}.
     *
     * @param json a JSON object fragment
     * @param key the field name
     * @return the decoded string value, or empty if absent, not a string,
     *         blank, or the document is malformed
     */
    static Optional<String> stringField(String json, String key) {
        if (json == null) {
            return Optional.empty();
        }
        int keyIdx = indexOfKey(json, key);
        if (keyIdx < 0) {
            return Optional.empty();
        }
        int colon = json.indexOf(':', keyIdx);
        if (colon < 0) {
            return Optional.empty();
        }
        int quoteStart = skipWhitespace(json, colon + 1);
        if (quoteStart >= json.length() || json.charAt(quoteStart) != '"') {
            return Optional.empty();
        }
        StringBuilder value = new StringBuilder();
        int i = quoteStart + 1;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                value.append(unescape(json.charAt(i + 1)));
                i += 2;
                continue;
            }
            if (c == '"') {
                String result = value.toString();
                return result.isBlank() ? Optional.empty() : Optional.of(result);
            }
            value.append(c);
            i++;
        }
        return Optional.empty();
    }

    private static char unescape(char escaped) {
        return switch (escaped) {
            case 'n' -> '\n';
            case 't' -> '\t';
            case 'r' -> '\r';
            default -> escaped; // covers \", \\, \/ and anything else verbatim
        };
    }

    /**
     * Finds the index of a {@code "key"} token used as an object key (i.e.
     * immediately followed, after optional whitespace, by a colon).
     */
    private static int indexOfKey(String json, String key) {
        String needle = "\"" + key + "\"";
        int from = 0;
        while (true) {
            int idx = json.indexOf(needle, from);
            if (idx < 0) {
                return -1;
            }
            int after = skipWhitespace(json, idx + needle.length());
            if (after < json.length() && json.charAt(after) == ':') {
                return idx;
            }
            from = idx + needle.length();
        }
    }

    private static int skipWhitespace(String s, int from) {
        int i = from;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    /**
     * Returns the index of the closing character that balances the opening
     * character at {@code openIdx}, ignoring braces/brackets inside quoted
     * strings, or {@code -1} if unbalanced.
     */
    private static int matchBalanced(String s, int openIdx, char open, char close) {
        int depth = 0;
        boolean inString = false;
        for (int i = openIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++; // skip escaped character
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == open) {
                depth++;
            } else if (c == close) {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }
}
