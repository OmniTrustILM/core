package com.otilm.core.signing.contentsigning;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * One document of a content-signing batch.
 *
 * @param identifier the caller-chosen identifier, used to identify the document in result and failures
 * @param content the document itself, or its digest when the batch travels as digests
 * @param authorizedDigest the digest the caller authorized, against which the binding gate checks the connector's echo;
 * {@code null} when the protocol authorizes no digest
 */
public record ContentSigningItem(String identifier, byte[] content, byte[] authorizedDigest) {

    public ContentSigningItem {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(content, "content");
        content = content.clone();
        authorizedDigest = authorizedDigest == null ? null : authorizedDigest.clone();
    }

    /** Its batch skips the binding gate. */
    public static ContentSigningItem withoutAuthorizedDigest(String identifier, byte[] content) {
        return new ContentSigningItem(identifier, content, null);
    }

    @Override
    public byte[] content() {
        return content.clone();
    }

    @Override
    public byte[] authorizedDigest() {
        return authorizedDigest == null ? null : authorizedDigest.clone();
    }

    public boolean carriesAuthorizedDigest() {
        return authorizedDigest != null;
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
                + " bytes, authorizedDigest="
                + (authorizedDigest == null ? null : HexFormat.of().formatHex(authorizedDigest)) + "]";
    }
}
