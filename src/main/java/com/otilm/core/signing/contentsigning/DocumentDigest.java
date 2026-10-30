package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A document digest and the algorithm that produced it. A digest cannot be interpreted without its algorithm, so the
 * two travel as one value.
 */
public record DocumentDigest(DigestAlgorithm algorithm, byte[] value) {

    /**
     * Copies the digest in, so a caller that reuses its buffer cannot change what was authorized after the fact.
     */
    public DocumentDigest {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(value, "value");
        value = value.clone();
    }

    /** Copies the digest out, so a consumer cannot reach back through the accessor and alter it. */
    @Override
    public byte[] value() {
        return value.clone();
    }

    /** The digest length, free of the copy {@link #value()} has to make. */
    public int length() {
        return value.length;
    }

    /** Whether the digest is as long as its algorithm produces; a shorter or longer one came from no document. */
    public boolean hasLengthOfItsAlgorithm() {
        return value.length == algorithm.getDigestSizeBytes();
    }

    /** Compares the digest by value in constant time, which a record's generated {@code equals} would not do. */
    @Override
    public boolean equals(Object other) {
        return other instanceof DocumentDigest digest && algorithm == digest.algorithm
                && MessageDigest.isEqual(value, digest.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, Arrays.hashCode(value));
    }

    /** A digest is not customer content, so it stays legible in a log line. */
    @Override
    public String toString() {
        return "DocumentDigest[algorithm=" + algorithm.getCode() + ", value=" + HexFormat.of().formatHex(value) + "]";
    }
}
