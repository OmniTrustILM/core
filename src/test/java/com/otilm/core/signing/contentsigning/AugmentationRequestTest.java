package com.otilm.core.signing.contentsigning;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AugmentationRequestTest {

    private static final byte[] FOREIGN_DOCUMENT = "a document signed elsewhere".getBytes();

    @Test
    void reportsTheDocumentSizeInsteadOfItsContent_whenRendered() {
        // given: the document was signed by a customer, so a log line must not carry it
        AugmentationRequest request = new AugmentationRequest(FOREIGN_DOCUMENT, null);

        // when
        String rendered = request.toString();

        // then
        assertThat(rendered).contains(FOREIGN_DOCUMENT.length + " bytes").doesNotContain("a document signed elsewhere");
    }

    @Test
    void equalsAnotherRequest_whenTheDocumentBytesAreEqual() {
        // given: distinct arrays, because a record's generated equals would compare them by identity
        AugmentationRequest one = new AugmentationRequest(FOREIGN_DOCUMENT, null);
        AugmentationRequest other = new AugmentationRequest(FOREIGN_DOCUMENT.clone(), null);

        // when
        boolean equal = one.equals(other);

        // then
        assertThat(equal).isTrue();
        assertThat(one).hasSameHashCodeAs(other);
    }

    @Test
    void differsFromAnotherRequest_whenTheDocumentsDiffer() {
        // given
        AugmentationRequest request = new AugmentationRequest(FOREIGN_DOCUMENT, null);
        AugmentationRequest another = new AugmentationRequest("another".getBytes(), null);

        // when
        boolean equal = request.equals(another);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void keepsTheDocumentItWasGiven_whenEitherSideMutatesItsBuffer() {
        // given: a buffer the caller still holds
        byte[] caller = FOREIGN_DOCUMENT.clone();
        AugmentationRequest request = new AugmentationRequest(caller, null);

        // when: both sides mutate what they can reach
        caller[0] = 'X';
        request.signedDocument()[1] = 'Y';

        // then: the request still holds what it was given
        assertThat(request.signedDocument()).isEqualTo(FOREIGN_DOCUMENT);
    }
}
