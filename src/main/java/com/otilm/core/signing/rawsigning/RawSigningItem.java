package com.otilm.core.signing.rawsigning;

import java.util.Arrays;
import java.util.Objects;

/**
 * One digest of a raw signing batch, under the identifier the caller chose for it.
 *
 * @param identifier the caller-chosen identifier, unique within the batch
 * @param digest the digest to sign as it is
 */
public record RawSigningItem(String identifier, byte[] digest) {

    /** Copies the digest in, so a caller that reuses its buffer cannot change what is signed. */
    public RawSigningItem {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(digest, "digest");
        digest = digest.clone();
    }

    /** Copies the digest out, so a consumer cannot reach back through the accessor and alter it. */
    @Override
    public byte[] digest() {
        return digest.clone();
    }

    /** The digest length, free of the copy {@link #digest()} has to make. */
    public int digestLength() {
        return digest.length;
    }

    /** A record's generated {@code equals} would compare the digest by identity. */
    @Override
    public boolean equals(Object other) {
        return other instanceof RawSigningItem item && identifier.equals(item.identifier)
                && Arrays.equals(digest, item.digest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier, Arrays.hashCode(digest));
    }

    /** Neither a digest nor a signature is log material, so only the digest's size is printed. */
    @Override
    public String toString() {
        return "RawSigningItem[identifier=" + identifier + ", digest=" + digest.length + " bytes]";
    }
}
