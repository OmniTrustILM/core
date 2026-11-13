package com.otilm.core.signing.contentsigning;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * One document of a content-signing batch.
 *
 * @param identifier the caller-chosen identifier, used to identify the document in result and failures
 * @param content the document itself, or its digest when the batch travels as digests
 * @param authorizedDigest the digest the caller authorized, against which the binding gate checks the connector's echo
 */
public record ContentSigningItem(String identifier, byte[] content, byte[] authorizedDigest) {

    public ContentSigningItem {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(authorizedDigest, "authorizedDigest");
        content = content.clone();
        authorizedDigest = authorizedDigest.clone();
    }

    @Override
    public byte[] content() {
        return content.clone();
    }

    @Override
    public byte[] authorizedDigest() {
        return authorizedDigest.clone();
    }

    /** A record's generated {@code equals} would compare the bytes by identity, so two equal items differ. */
    @Override
    public boolean equals(Object other) {
        return other instanceof ContentSigningItem item && identifier.equals(item.identifier)
                && Arrays.equals(content, item.content) && Arrays.equals(authorizedDigest, item.authorizedDigest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier, Arrays.hashCode(content), Arrays.hashCode(authorizedDigest));
    }

    /** An inline document is customer content, so only its size is logged. */
    @Override
    public String toString() {
        return "ContentSigningItem[identifier=" + identifier + ", content=" + content.length
                + " bytes, authorizedDigest=" + HexFormat.of().formatHex(authorizedDigest) + "]";
    }
}
