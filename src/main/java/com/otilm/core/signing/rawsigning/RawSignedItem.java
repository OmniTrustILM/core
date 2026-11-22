package com.otilm.core.signing.rawsigning;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * The signature of one digest of a raw signing batch.
 *
 * @param identifier the identifier the caller gave the digest
 * @param signature the signature over the digest
 * @param signingRecordUuid the signing record of the digest, or {@code null} when the profile records nothing or its
 * best-effort records could not be staged
 */
public record RawSignedItem(String identifier, byte[] signature, UUID signingRecordUuid) {

    public RawSignedItem {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(signature, "signature");
        signature = signature.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    /** A record's generated {@code equals} would compare the signature by identity. */
    @Override
    public boolean equals(Object other) {
        return other instanceof RawSignedItem item && identifier.equals(item.identifier)
                && Arrays.equals(signature, item.signature)
                && Objects.equals(signingRecordUuid, item.signingRecordUuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier, Arrays.hashCode(signature), signingRecordUuid);
    }

    /** Neither a digest nor a signature is log material, so only the signature's size is printed. */
    @Override
    public String toString() {
        return "RawSignedItem[identifier=" + identifier + ", signature=" + signature.length
                + " bytes, signingRecordUuid=" + signingRecordUuid + "]";
    }
}
