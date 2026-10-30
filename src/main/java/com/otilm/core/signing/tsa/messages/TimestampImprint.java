package com.otilm.core.signing.tsa.messages;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import org.springframework.lang.NonNull;

/**
 * What a timestamp is to be taken over: a digest and the algorithm that produced it.
 *
 * @param algorithm the algorithm that produced {@code value}
 * @param value the digest itself
 */
public record TimestampImprint(DigestAlgorithm algorithm, byte[] value) {

    /** Copies the digest in, so a caller that reuses its buffer cannot change what is stamped after the fact. */
    public TimestampImprint {
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

    /** Compares the imprint by value in constant time, which a record's generated {@code equals} would not do. */
    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof TimestampImprint imprint && algorithm == imprint.algorithm
                && MessageDigest.isEqual(value, imprint.value);
    }

    @Override
    public int hashCode() {
        return 31 * algorithm.hashCode() + Arrays.hashCode(value);
    }

    @Override
    @NonNull
    public String toString() {
        return "TimestampImprint[%s:%s]".formatted(algorithm.getCode(), HexFormat.of().formatHex(value));
    }
}
