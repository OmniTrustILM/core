package com.czertainly.core.signing.tsa.messages;

import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;

/**
 * Result of processing a timestamp request — either {@link Granted} with
 * the DER-encoded timestamp token (CMS {@code ContentInfo}), or {@link Rejected} with failure info and status string.
 */
public sealed interface TspResponse {

    record Granted(byte[] timestampBytes) implements TspResponse {}

    record Rejected(TspFailureInfo failureInfo, String statusString) implements TspResponse {}


    static TspResponse granted(byte[] responseBytes) {
        return new Granted(responseBytes);
    }

    static TspResponse rejected(TspFailureInfo failureInfo, String statusString) {
        return new Rejected(failureInfo, statusString);
    }
}
