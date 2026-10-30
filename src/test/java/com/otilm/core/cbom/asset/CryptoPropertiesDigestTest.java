package com.otilm.core.cbom.asset;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoPropertiesDigestTest {

    @Test
    void anAbsentPayloadHasNoHash() {
        CryptoPropertiesDigest digest = CryptoPropertiesDigest.of(null);

        assertThat(digest.leafCount()).isZero();
        assertThat(digest.hash())
                .describedAs("ck_crypto_asset_properties_pair requires payload and hash to be absent together")
                .isNull();
    }

    @Test
    void anEmptyPayloadHasAHashButNoLeaves() {
        CryptoPropertiesDigest digest = CryptoPropertiesDigest.of(Map.of());

        assertThat(digest.leafCount()).isZero();
        assertThat(digest.hash()).isNotNull().hasSize(64);
    }

    @Test
    void richnessCountsScalarsAtEveryDepth() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("assetType", "algorithm");
        properties
                .put("algorithmProperties",
                        Map.of("primitive", "signature", "parameterSetIdentifier", "2048", "padding", "pkcs1v15"));
        properties.put("certificateProperties", Map.of());
        properties.put("subjectAlternativeNames", List.of("a", "b"));

        assertThat(CryptoPropertiesDigest.of(properties).leafCount()).isEqualTo(6);
    }

    @Test
    void anEmptyContainerAddsNoRichness() {
        Map<String, Object> withEmptyContainers = Map.of("a", Map.of(), "b", List.of(), "c", Map.of("d", Map.of()));

        assertThat(CryptoPropertiesDigest.of(withEmptyContainers).leafCount())
                .describedAs("an object full of empty objects must not out-rank a source that reported a curve")
                .isZero();
    }

    @Test
    void aRicherPayloadOutranksALeanerOne() {
        int lean = CryptoPropertiesDigest.of(Map.of("primitive", "signature")).leafCount();
        int rich = CryptoPropertiesDigest.of(Map.of("primitive", "signature", "curve", "P-256")).leafCount();

        assertThat(rich).isGreaterThan(lean);
    }

    @Test
    void memberOrderDoesNotChangeTheHash() {
        Map<String, Object> oneOrder = new LinkedHashMap<>();
        oneOrder.put("primitive", "signature");
        oneOrder.put("curve", "P-256");
        Map<String, Object> otherOrder = new LinkedHashMap<>();
        otherOrder.put("curve", "P-256");
        otherOrder.put("primitive", "signature");

        assertThat(CryptoPropertiesDigest.of(oneOrder).hash())
                .describedAs("otherwise a re-parse of the same document could elect a different source every sync")
                .isEqualTo(CryptoPropertiesDigest.of(otherOrder).hash());
    }

    @Test
    void differentContentHashesDifferently() {
        assertThat(CryptoPropertiesDigest.of(Map.of("curve", "P-256")).hash())
                .isNotEqualTo(CryptoPropertiesDigest.of(Map.of("curve", "P-384")).hash());
    }

    /**
     * An explicit JSON null is a declared absence, not content. Counting it as a leaf let an all-null payload out-rank
     * a source that reported a real value, and the merge election then hid the real one.
     */
    @Test
    void anExplicitNullIsNotContent() {
        java.util.Map<String, Object> allNull = new java.util.LinkedHashMap<>();
        allNull.put("primitive", null);
        allNull.put("mode", null);

        assertThat(CryptoPropertiesDigest.leafCount(allNull)).isZero();
        assertThat(CryptoPropertiesDigest.leafCount(java.util.Map.of("curve", "P-256")))
                .describedAs("a payload with one real value must out-rank a payload of declared absences")
                .isGreaterThan(CryptoPropertiesDigest.leafCount(allNull));
    }

    /**
     * A blank string describes nothing, so it must not out-rank a source that said nothing.
     *
     * <p>
     * The election stores the richest payload verbatim, so richness decides which producer's description becomes the
     * row. Counting {@code "   "} as content let a source saying {@code {"curve":"   "}} beat one that omitted the
     * field entirely -- whitespace winning outright and becoming the stored view. Measured against the ratified
     * reference over 2364 corpus payloads: this is the only rule the two disagreed on.
     */
    @Test
    void aBlankStringIsAbsenceRatherThanContent() {
        assertThat(CryptoPropertiesDigest.of(Map.of("curve", "   ")).leafCount()).isZero();
        assertThat(CryptoPropertiesDigest.of(Map.of("curve", "")).leafCount()).isZero();
        assertThat(CryptoPropertiesDigest.of(Map.of("curve", "P-256")).leafCount()).isOne();
    }

    /**
     * Blankness follows the specification's whitespace set, not {@link String#isBlank()}.
     *
     * <p>
     * {@code isBlank} consults {@link Character#isWhitespace}, which does not consider a no-break space whitespace --
     * and a no-break space is exactly what arrives in text pasted out of a document or a spreadsheet.
     */
    @Test
    void aNoBreakSpaceIsBlankToo() {
        String noBreakSpace = Character.toString(0x00A0);
        boolean theJdkCallsItBlank = noBreakSpace.isBlank();

        assertThat(theJdkCallsItBlank)
                .describedAs("the JDK does not agree, which is why this rule is explicit")
                .isFalse();
        assertThat(CryptoPropertiesDigest.of(Map.of("curve", noBreakSpace)).leafCount()).isZero();
    }

    /**
     * A richer description beats a blank one, which is the property the election actually depends on.
     *
     * <p>
     * Stated as a comparison rather than as two counts, because the counts exist only to be ordered.
     */
    @Test
    void aRealValueOutranksWhitespaceAtEveryDepth() {
        int whitespace = CryptoPropertiesDigest
                .of(Map.of("algorithmProperties", Map.of("curve", "   ", "mode", " ")))
                .leafCount();
        int stated = CryptoPropertiesDigest.of(Map.of("algorithmProperties", Map.of("curve", "P-256"))).leafCount();

        assertThat(whitespace).isZero();
        assertThat(stated).isGreaterThan(whitespace);
    }
}
