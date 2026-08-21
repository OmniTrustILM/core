package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.signature.SignatureLevel;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SignedContentTest {

    private static final byte[] DOCUMENT = "signed document".getBytes();

    @Test
    void twoResultsHoldingEqualDocumentBytesAreEqual() {
        // given: distinct arrays, because a record's generated equals would compare them by identity
        SignedContent one = new SignedContent(DOCUMENT, SignatureLevel.SIGNED, List.of());
        SignedContent other = new SignedContent(DOCUMENT.clone(), SignatureLevel.SIGNED, List.of());

        // when / then
        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }

    @Test
    void resultsDifferingInLevelOrSerialsAreNotEqual() {
        // given
        SignedContent signed = new SignedContent(DOCUMENT, SignatureLevel.SIGNED, List.of());

        // when / then
        assertThat(signed)
                .isNotEqualTo(new SignedContent(DOCUMENT, SignatureLevel.TIMESTAMPED, List.of()))
                .isNotEqualTo(new SignedContent(DOCUMENT, SignatureLevel.SIGNED, List.of(BigInteger.ONE)))
                .isNotEqualTo(new SignedContent("other".getBytes(), SignatureLevel.SIGNED, List.of()));
    }

    @Test
    void theDocumentIsNeverStoredOrHandedOutByReference() {
        // given
        byte[] mutable = DOCUMENT.clone();
        SignedContent signed = new SignedContent(mutable, SignatureLevel.SIGNED, List.of());

        // when: mutate both the array passed in and the one handed back
        mutable[0] = 'X';
        signed.signedDocument()[1] = 'X';

        // then: neither reaches the stored copy
        assertThat(signed.signedDocument()).isEqualTo(DOCUMENT);
    }

    @Test
    void toStringReportsTheDocumentSizeInsteadOfItsContent() {
        // given: the signed document is customer content, so a log line must not carry it
        SignedContent signed = new SignedContent(DOCUMENT, SignatureLevel.SIGNED, List.of(BigInteger.valueOf(0x2a)));

        // when
        String rendered = signed.toString();

        // then
        assertThat(rendered)
                .contains(DOCUMENT.length + " bytes")
                .contains("SIGNED")
                .contains("42")
                .doesNotContain("signed document");
    }
}
