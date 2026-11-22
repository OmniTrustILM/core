package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.signature.SignatureLevel;
import java.math.BigInteger;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class SignedContentTest {

    private static final byte[] DOCUMENT = "signed document".getBytes();

    @Test
    void comparesEqual_whenTheDocumentBytesMatch() {
        // given: distinct arrays, because a record's generated equals would compare them by identity
        SignedContent one = new SignedContent(DOCUMENT, "application/pdf", SignatureLevel.SIGNED, List.of());
        SignedContent other = new SignedContent(DOCUMENT.clone(), "application/pdf", SignatureLevel.SIGNED, List.of());

        // when
        boolean equal = one.equals(other);
        boolean sameHashCode = one.hashCode() == other.hashCode();

        // then
        assertThat(equal).isTrue();
        assertThat(sameHashCode).isTrue();
    }

    @ParameterizedTest
    @MethodSource("resultsDifferingInOneComponent")
    void comparesUnequal_whenOneComponentDiffers(SignedContent different) {
        // given
        SignedContent signed = new SignedContent(DOCUMENT, "application/pdf", SignatureLevel.SIGNED, List.of());

        // when
        boolean equal = signed.equals(different);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void refusesToCreate_whenTheMediaTypeIsMissing() {
        // given
        List<BigInteger> noSerials = List.of();

        // when
        ThrowingCallable create = () -> new SignedContent(DOCUMENT, null, SignatureLevel.SIGNED, noSerials);

        // then
        assertThatThrownBy(create).isInstanceOf(NullPointerException.class).hasMessageContaining("mediaType");
    }

    @Test
    void keepsItsOwnCopyOfTheDocument_whenEitherArrayIsMutated() {
        // given
        byte[] mutable = DOCUMENT.clone();
        SignedContent signed = new SignedContent(mutable, "application/pdf", SignatureLevel.SIGNED, List.of());

        // when: mutate both the array passed in and the one handed back
        mutable[0] = 'X';
        signed.output()[1] = 'X';

        // then: neither reaches the stored copy
        assertThat(signed.output()).isEqualTo(DOCUMENT);
    }

    @Test
    void rendersTheDocumentSizeInsteadOfItsContent_whenConvertedToString() {
        // given: the signed document is customer content, so a log line must not carry it
        SignedContent signed = new SignedContent(DOCUMENT, "application/pdf", SignatureLevel.SIGNED,
                List.of(BigInteger.valueOf(0x2a)));

        // when
        String rendered = signed.toString();

        // then
        assertThat(rendered)
                .contains(DOCUMENT.length + " bytes")
                .contains("SIGNED")
                .contains("42")
                .doesNotContain("signed document");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<SignedContent>> resultsDifferingInOneComponent() {
        return Stream
                .of(named("level",
                        new SignedContent(DOCUMENT, "application/pdf", SignatureLevel.TIMESTAMPED, List.of())),
                        named("timestamp serials",
                                new SignedContent(DOCUMENT, "application/pdf", SignatureLevel.SIGNED,
                                        List.of(BigInteger.ONE))),
                        named("document",
                                new SignedContent("other".getBytes(), "application/pdf", SignatureLevel.SIGNED,
                                        List.of())),
                        named("media type", new SignedContent(DOCUMENT, "application/octet-stream",
                                SignatureLevel.SIGNED, List.of())));
    }
}
