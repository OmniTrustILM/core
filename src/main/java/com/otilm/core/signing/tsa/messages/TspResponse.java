package com.otilm.core.signing.tsa.messages;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;

import java.util.Arrays;

/**
 * Result of processing a timestamp request — either {@link Granted} with
 * the DER-encoded timestamp token (CMS {@code ContentInfo}), or {@link Rejected} with failure info and status string.
 */
public sealed interface TspResponse {

    record Granted(byte[] timestampBytes) implements TspResponse {

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Granted(byte[] otherTimestampBytes))) return false;
            return Arrays.equals(timestampBytes, otherTimestampBytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(timestampBytes);
        }

        @Override
        public String toString() {
            return "Granted[timestampBytes=" + Arrays.toString(timestampBytes) + "]";
        }
    }

    record Rejected(TspFailureInfo failureInfo, String statusString) implements TspResponse {}


    static TspResponse granted(byte[] responseBytes) {
        return new Granted(responseBytes);
    }

    static TspResponse rejected(TspFailureInfo failureInfo, String statusString) {
        return new Rejected(failureInfo, statusString);
    }
}
