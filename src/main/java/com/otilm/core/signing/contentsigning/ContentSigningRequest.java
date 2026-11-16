package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import java.util.List;
import java.util.Objects;

/**
 * One content-signing run's input: a batch of documents signed the same way.
 *
 * @param targetLevel the requested level, capped by the profile's ceiling
 * @param transferMode how every document travels to the connector: inline, or as a digest
 * @param digestAlgorithm the algorithm of every authorized digest and of every digest the batch sends
 * @param items the documents in request order
 * @param signatureParameters the effective parameters {@code SignatureParameterResolver} produced
 */
public record ContentSigningRequest(SignatureLevel targetLevel, DocumentTransferMode transferMode,
        DigestAlgorithm digestAlgorithm, List<ContentSigningItem> items, SignatureParametersDto signatureParameters) {

    public ContentSigningRequest {
        Objects.requireNonNull(targetLevel, "targetLevel");
        Objects.requireNonNull(transferMode, "transferMode");
        Objects.requireNonNull(digestAlgorithm, "digestAlgorithm");
        items = List.copyOf(items);
        if (items.isEmpty()) {
            throw new IllegalArgumentException("A content-signing batch has no document");
        }
    }

    public List<String> identifiers() {
        return items.stream().map(ContentSigningItem::identifier).toList();
    }

    /** The item's document as it travels to the connector in the batch's transfer mode. */
    public DocumentTransferDto transferOf(ContentSigningItem item) {
        return switch (transferMode) {
            case INLINE -> new InlineDocumentTransferDto(item.content());
            case DIGEST_ONLY -> new DigestOnlyDocumentTransferDto(item.content(), digestAlgorithm);
        };
    }

    /** The digest the caller authorized for the item, under the batch's digest algorithm. */
    public DocumentDigest authorizedDigestOf(ContentSigningItem item) {
        return new DocumentDigest(digestAlgorithm, item.authorizedDigest());
    }
}
