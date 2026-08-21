package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.signature.SignatureLevel;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AugmentationRequestTest {

    private static final byte[] FOREIGN_DOCUMENT = "a document signed elsewhere".getBytes();

    @Test
    void toStringReportsTheDocumentSizeInsteadOfItsContent() {
        // given: the document was signed by a customer, so a log line must not carry it
        AugmentationRequest request = new AugmentationRequest(SignatureLevel.TIMESTAMPED, FOREIGN_DOCUMENT, null);

        // when
        String rendered = request.toString();

        // then
        assertThat(rendered).contains(FOREIGN_DOCUMENT.length + " bytes").contains("TIMESTAMPED");
        assertThat(rendered).doesNotContain("a document signed elsewhere");
    }

    @Test
    void copiesTheDocumentInAndOutSoNeitherSideCanAlterWhatIsAugmented() {
        // given: a buffer the caller still holds
        byte[] caller = FOREIGN_DOCUMENT.clone();
        AugmentationRequest request = new AugmentationRequest(SignatureLevel.TIMESTAMPED, caller, null);

        // when: both sides mutate what they can reach
        caller[0] = 'X';
        request.signedDocument()[1] = 'Y';

        // then: the request still holds what it was given
        assertThat(request.signedDocument()).isEqualTo(FOREIGN_DOCUMENT);
    }
}
