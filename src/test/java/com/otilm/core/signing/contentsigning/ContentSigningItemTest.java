package com.otilm.core.signing.contentsigning;

import java.util.HexFormat;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class ContentSigningItemTest {

    private static final byte[] DOCUMENT = "a document".getBytes();

    private static final byte[] DIGEST = HexFormat.of().parseHex("0a0b0c");

    private static final ContentSigningItem ITEM = new ContentSigningItem("first", DOCUMENT, DIGEST);

    @Test
    void equalsAnItemHoldingEqualBytes() {
        // given: distinct arrays, because a record's generated equals would compare them by identity
        var sameBytes = new ContentSigningItem("first", DOCUMENT.clone(), DIGEST.clone());

        // when
        boolean equal = ITEM.equals(sameBytes);

        // then
        assertThat(equal).isTrue();
        assertThat(sameBytes).hasSameHashCodeAs(ITEM);
    }

    @ParameterizedTest
    @MethodSource("otherThanTheItem")
    void differsFromAnythingElse(Object other) {
        // given — an object that differs from ITEM in one respect

        // when
        boolean equal = ITEM.equals(other);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void neverStoresOrHandsOutItsBytesByReference() {
        // given
        byte[] mutableDocument = DOCUMENT.clone();
        byte[] mutableDigest = DIGEST.clone();
        var item = new ContentSigningItem("first", mutableDocument, mutableDigest);

        // when: mutate the arrays passed in and the ones handed back
        mutableDocument[0] = 'X';
        mutableDigest[0] = 0;
        item.content()[1] = 'X';
        item.authorizedDigest()[1] = 0;

        // then
        assertThat(item).isEqualTo(ITEM);
    }

    @Test
    void reportsTheContentSizeInsteadOfItsBytes() {
        // given — ITEM, whose document is readable text

        // when
        String rendered = ITEM.toString();

        // then
        assertThat(rendered)
                .contains("first")
                .contains(DOCUMENT.length + " bytes")
                .contains("0a0b0c")
                .doesNotContain("a document");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<Object>> otherThanTheItem() {
        return Stream
                .of(named("another identifier", new ContentSigningItem("second", DOCUMENT, DIGEST)),
                        named("another content", new ContentSigningItem("first", "another".getBytes(), DIGEST)),
                        named("another authorized digest", new ContentSigningItem("first", DOCUMENT, new byte[3])),
                        named("another type", "first"));
    }
}
