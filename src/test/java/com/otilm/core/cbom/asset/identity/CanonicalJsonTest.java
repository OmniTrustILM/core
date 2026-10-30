package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the canonical payload to the reference's bytes rather than to any JSON library's defaults.
 *
 * <p>
 * Every case here covers a branch the validation corpus does not reach. Measured over 2355 real payloads, the corpus
 * carries no non-ASCII key, no non-ASCII value and no fractional number at all -- so a green corpus run says nothing
 * about any of them, and each needs a hand-written case. That gap is not hypothetical: probing these branches directly
 * is what found the two number-formatting divergences below.
 */
class CanonicalJsonTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    /**
     * Keys sort by code point, not by UTF-16 code unit.
     *
     * <p>
     * The two orders disagree for any key above the basic multilingual plane: an astral character is a surrogate pair,
     * which compares <em>below</em> {@code U+E000..U+FFFF} as code units and above it as code points. Java's natural
     * String ordering is the wrong one here.
     */
    @Test
    void objectKeysSortByCodePointNotByUtf16Unit() {
        assertThat(canonicalize("{\"z\":\"a\",\"\uD83D\uDE00\":1,\"\uFFFD\":2}"))
                .isEqualTo("{\"z\":\"a\",\"\uFFFD\":2,\"\uD83D\uDE00\":1}");
    }

    @Test
    void nonAsciiPassesThroughUnescaped() {
        assertThat(canonicalize("{\"k\u00e9y\":\"caf\u00e9\"}")).isEqualTo("{\"k\u00e9y\":\"caf\u00e9\"}");
    }

    /** Lowercase hex, and only below U+0020. Jackson escapes with uppercase hex, which is a different byte. */
    @Test
    void controlCharactersEscapeAsLowercaseHexWithTheShortcuts() {
        assertThat(canonicalize("{\"v\":\"a\\u0001b\"}")).isEqualTo("{\"v\":\"a\\u0001b\"}");
        assertThat(canonicalize("{\"v\":\"tab\\there\"}")).isEqualTo("{\"v\":\"tab\\there\"}");
        assertThat(canonicalize("{\"v\":\"\\u007f\"}"))
                .describedAs("DEL is not a control character here")
                .isEqualTo("{\"v\":\"\u007f\"}");
    }

    /**
     * An integral number renders as an integer whichever way it was spelled.
     *
     * <p>
     * One producer really does ship {@code specVersion: 999} as a number while everyone else ships a string, and two
     * payloads differing only in that spelling must not produce different digests.
     */
    @ParameterizedTest
    @CsvSource({"999.0, 999", "3.0, 3", "-0.0, 0", "1e20, 100000000000000000000", "1e21, 1000000000000000000000"})
    void anIntegralNumberRendersAsAnInteger(String input, String expected) {
        assertThat(canonicalize("{\"v\":" + input + "}")).isEqualTo("{\"v\":" + expected + "}");
    }

    /**
     * Fractional numbers use the reference's rendering, which is neither {@code toPlainString} nor RFC 8785.
     *
     * <p>
     * {@code BigDecimal.toPlainString} writes {@code 1e-7} as {@code 0.0000001}; the reference writes {@code 1e-07};
     * RFC 8785, which the specification cites for this payload, mandates ECMAScript formatting and would write
     * {@code 1e-7}. Three spellings, and the one that matters is the reference's, because that is what the shipped
     * conformance vectors were generated against.
     */
    @ParameterizedTest
    @CsvSource({"0.1, 0.1", "1.5, 1.5", "1e-7, 1e-07", "2.5e-10, 2.5e-10", "0.0001, 0.0001", "0.00001, 1e-05"})
    void aFractionalNumberUsesTheReferenceRendering(String input, String expected) {
        assertThat(canonicalize("{\"v\":" + input + "}")).isEqualTo("{\"v\":" + expected + "}");
    }

    /**
     * The shortest round-tripping decimal, not the JDK's shortest.
     *
     * <p>
     * {@code Double.toString(Double.MIN_VALUE)} is {@code 4.9E-324}, which round-trips but is not the shortest form. A
     * round-trip check alone would therefore accept it and write a different byte from the reference's {@code 5e-324}.
     * This is the whole reason the renderer searches for fewest significant digits rather than parsing what the JDK
     * produced.
     */
    @Test
    void theSmallestSubnormalTakesItsShortestSpellingNotTheJdkSpelling() {
        assertThat(Double.toString(Double.MIN_VALUE)).isEqualTo("4.9E-324");

        assertThat(canonicalize("{\"v\":5e-324}")).isEqualTo("{\"v\":5e-324}");
    }

    /** An integer token keeps arbitrary precision, as the reference's integers do. */
    @Test
    void anIntegerBeyondLongRangeKeepsEveryDigit() {
        assertThat(canonicalize("{\"v\":1234567890123456789012345678}"))
                .isEqualTo("{\"v\":1234567890123456789012345678}");
    }

    /**
     * A fractional token is narrowed to a double first, deliberately: the reference parses JSON floats into machine
     * doubles, so a literal carrying more precision than a double holds is the same value there.
     */
    @Test
    void aFractionalLiteralIsNarrowedToWhatADoubleHolds() {
        assertThat(canonicalize("{\"v\":0.1000000000000000000001}")).isEqualTo("{\"v\":0.1}");
    }

    /**
     * Document-internal references are stripped before hashing, in both the 1.6 and the 1.7 spelling.
     *
     * <p>
     * 1.7 renamed every one of them, so keeping them makes the hash backstop parity-unsafe: measured, it produced 13
     * material rows where 8 are correct, purely because one asset carries {@code algorithmRef} under 1.6 and
     * {@code relatedCryptographicAssets} under 1.7.
     */
    @Test
    void theSameAssetHashesAlikeUnderBothSchemaVersions() {
        String underOneSix = "{\"assetType\":\"algorithm\",\"algorithmRef\":\"crypto/algorithm/aes@1\"}";
        String underOneSeven = "{\"assetType\":\"algorithm\",\"relatedCryptographicAssets\":[{\"ref\":\"other\"}]}";

        assertThat(projectionDigest(underOneSix)).isEqualTo(projectionDigest(underOneSeven));
    }

    @Test
    void referencesAreStrippedAtEveryDepth() {
        assertThat(canonicalize(
                CanonicalJson.strippedProjection(read("{\"a\":{\"b\":[{\"algorithmRef\":\"x\",\"keep\":1}]}}"))))
                .isEqualTo("{\"a\":{\"b\":[{\"keep\":1}]}}");
    }

    /**
     * A non-finite number is refused rather than given an invented spelling.
     *
     * <p>
     * The reference refuses too. The walker turns this into a per-component skip, which is what a document carrying
     * {@code 1e400} deserves -- it must not fail the whole run, and it must not silently hash as something else.
     */
    @Test
    void aNonFiniteNumberIsRefusedRatherThanSpelled() {
        assertThatThrownBy(() -> canonicalize("{\"v\":1e400}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-finite");
    }

    @Test
    void emptyContainersAndNullsRenderAsTheReferenceRendersThem() {
        assertThat(canonicalize("{\"a\":{},\"b\":[],\"c\":null,\"d\":true,\"e\":false}"))
                .isEqualTo("{\"a\":{},\"b\":[],\"c\":null,\"d\":true,\"e\":false}");
    }

    /** Array order is preserved: only object keys sort. */
    @Test
    void arrayOrderSurvivesCanonicalization() {
        assertThat(canonicalize("{\"v\":[3,1,2]}")).isEqualTo("{\"v\":[3,1,2]}");
    }

    private static String canonicalize(String json) {
        return CanonicalJson.canonicalize(read(json));
    }

    private static String canonicalize(JsonNode node) {
        return CanonicalJson.canonicalize(node);
    }

    private static String projectionDigest(String json) {
        return CanonicalJson.projectionDigest(read(json));
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("test fixture is not JSON: " + json, e);
        }
    }
}
