package com.otilm.core.signing.record;

import java.math.BigInteger;
import java.util.List;

/**
 * The rendering of {@code timestampTokenSerialNumbers}, which is the only join between a content signature's record and
 * the timestamp records it points at. Both sides of the join must render a serial identically, so both call this.
 *
 * <p>
 * Unpadded lower-case hex, no {@code 0x} prefix and no leading zeros, as the Signing Record contract states.
 * </p>
 */
public final class TimestampTokenSerialNumbers {

    private TimestampTokenSerialNumbers() {
    }

    public static String hex(BigInteger serialNumber) {
        return serialNumber.toString(16);
    }

    public static List<String> hex(List<BigInteger> serialNumbers) {
        return serialNumbers.stream().map(TimestampTokenSerialNumbers::hex).toList();
    }
}
