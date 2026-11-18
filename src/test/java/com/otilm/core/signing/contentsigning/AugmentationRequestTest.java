package com.otilm.core.signing.contentsigning;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AugmentationRequestTest {

    private static final byte[] FOREIGN_DOCUMENT = "a document signed elsewhere".getBytes();

    @Test
    void toStringReportsTheDocumentSizeInsteadOfItsContent() {
        // given: the document was signed by a customer, so a log line must not carry it
        AugmentationRequest request = new AugmentationRequest(FOREIGN_DOCUMENT, null);

        // when
        String rendered = request.toString();

        // then
        assertThat(rendered).contains(FOREIGN_DOCUMENT.length + " bytes").doesNotContain("a document signed elsewhere");
    }

    @Test
    void twoRequestsHoldingEqualDocumentBytesAreEqual() {
        // given: distinct arrays, because a record's generated equals would compare them by identity
        AugmentationRequest one = new AugmentationRequest(FOREIGN_DOCUMENT, null);
        AugmentationRequest other = new AugmentationRequest(FOREIGN_DOCUMENT.clone(), null);

        // when / then
        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }

    @Test
    void requestsDifferingInTheDocumentAreNotEqual() {
        // given
        AugmentationRequest request = new AugmentationRequest(FOREIGN_DOCUMENT, null);

        // when / then
        assertThat(request).isNotEqualTo(new AugmentationRequest("another".getBytes(), null));
    }

    @Test
    void copiesTheDocumentInAndOutSoNeitherSideCanAlterWhatIsAugmented() {
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
