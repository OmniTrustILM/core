package com.otilm.core.signing.tsa.messages;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.springframework.lang.NonNull;

/**
 * A timestamp token the engine has issued, with the artifacts a caller needs to trace it back to its signing record.
 *
 * @param encoded the DER-encoded token (CMS {@code ContentInfo})
 * @param serialNumber the token's serial number, which its signing record carries in the display name and the request
 * metadata
 * @param genTime the generation time embedded in the token
 */
public record IssuedTimestamp(byte[] encoded, BigInteger serialNumber, Instant genTime) {

    public IssuedTimestamp {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(genTime, "genTime");
        encoded = encoded.clone();
    }

    @Override
    public byte[] encoded() {
        return encoded.clone();
    }

    /** Compares the token by value, which a record's generated {@code equals} would not do for its array. */
    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof IssuedTimestamp issued && serialNumber.equals(issued.serialNumber)
                && genTime.equals(issued.genTime) && Arrays.equals(encoded, issued.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(serialNumber, genTime) + Arrays.hashCode(encoded);
    }

    /** Renders the serial and generation time; the token itself is too long to be useful in a log line. */
    @Override
    @NonNull
    public String toString() {
        return "IssuedTimestamp[serialNumber=%s, genTime=%s, encoded=%d bytes]"
                .formatted(serialNumber.toString(16), genTime, encoded.length);
    }
}
