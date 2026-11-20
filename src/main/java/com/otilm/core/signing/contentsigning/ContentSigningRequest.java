package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import java.util.List;
import java.util.Objects;

/**
 * One content-signing run's input: a batch of documents signed the same way.
 *
 * @param transferMode how every document travels to the connector: inline, or as a digest
 * @param digestAlgorithm the algorithm of every authorized digest and of every digest the batch sends; {@code null} for
 * an inline batch without authorized digests
 * @param items the documents in request order
 * @param requestAttributes the values the request sets for the formatter's request attributes
 */
public record ContentSigningRequest(DocumentTransferMode transferMode, DigestAlgorithm digestAlgorithm,
        List<ContentSigningItem> items, List<RequestAttribute> requestAttributes) {

    public ContentSigningRequest {
        Objects.requireNonNull(transferMode, "transferMode");
        items = List.copyOf(items);
        requestAttributes = List.copyOf(requestAttributes);
        if (items.isEmpty()) {
            throw new IllegalArgumentException("A content-signing batch has no document");
        }
        if (items.stream().anyMatch(ContentSigningItem::carriesAuthorizedDigest)
                && !everyItemCarriesAuthorizedDigest(items)) {
            throw new IllegalArgumentException("An authorized digest belongs to every document or none");
        }
        boolean carriesDigests = carriesDigests(transferMode, items);
        if (digestAlgorithm == null && carriesDigests) {
            throw new IllegalArgumentException("A batch that sends or authorizes digests names their digestAlgorithm");
        }
        if (digestAlgorithm != null && !carriesDigests) {
            throw new IllegalArgumentException("A batch without digests names no digestAlgorithm");
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

    /** Whether the caller authorized a digest per document. The binding gate checks the connector's echo against it. */
    public boolean bindsAuthorizedDigests() {
        return everyItemCarriesAuthorizedDigest(items);
    }

    /** Whether the batch sends or authorizes digests, all of them under its {@code digestAlgorithm}. */
    public boolean carriesDigests() {
        return carriesDigests(transferMode, items);
    }

    /** The digest the caller authorized for the item, under the batch's digest algorithm. */
    public DocumentDigest authorizedDigestOf(ContentSigningItem item) {
        if (!bindsAuthorizedDigests()) {
            throw new IllegalStateException("The batch binds no authorized digests");
        }
        return new DocumentDigest(digestAlgorithm, item.authorizedDigest());
    }

    private static boolean carriesDigests(DocumentTransferMode transferMode, List<ContentSigningItem> items) {
        return transferMode == DocumentTransferMode.DIGEST_ONLY || everyItemCarriesAuthorizedDigest(items);
    }

    private static boolean everyItemCarriesAuthorizedDigest(List<ContentSigningItem> items) {
        return items.stream().allMatch(ContentSigningItem::carriesAuthorizedDigest);
    }
}
