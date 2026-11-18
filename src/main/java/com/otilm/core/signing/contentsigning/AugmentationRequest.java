package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import java.util.Arrays;
import java.util.Objects;

/**
 * One augmentation run's input: a document signed elsewhere and any detached content, raised to the profile's level.
 *
 * @param signedDocument the document as signed elsewhere
 * @param detachedContent the content beside a detached signature, or {@code null} for an enveloped one
 */
public record AugmentationRequest(byte[] signedDocument, DocumentTransferDto detachedContent) {

    /** Copies the document in, so a caller that reuses its buffer cannot change what is augmented after the fact. */
    public AugmentationRequest {
        Objects.requireNonNull(signedDocument, "signedDocument");
        signedDocument = signedDocument.clone();
    }

    /** Copies the document out, so a consumer cannot reach back through the accessor and alter it. */
    @Override
    public byte[] signedDocument() {
        return signedDocument.clone();
    }

    /** A record's generated {@code equals} would compare the document by identity, so two equal requests differ. */
    @Override
    public boolean equals(Object other) {
        return other instanceof AugmentationRequest request && Arrays.equals(signedDocument, request.signedDocument)
                && Objects.equals(detachedContent, request.detachedContent);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(signedDocument), detachedContent);
    }

    /** Reports the document's size rather than its bytes, because a document a customer signed is not log material. */
    @Override
    public String toString() {
        return "AugmentationRequest[signedDocument=" + signedDocument.length + " bytes, detachedContent="
                + detachedContent + "]";
    }
}
