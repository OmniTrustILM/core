package com.otilm.core.service.handler.authority;

import com.otilm.api.model.common.error.ErrorCode;

/**
 * Shared classification of connector error codes that recur across the adapter and the async
 * poll listener. Centralized so the two consumers don't drift when a new "not tracked" code is
 * introduced.
 */
public final class ConnectorOperationErrorCodes {

    private ConnectorOperationErrorCodes() {
    }

    /**
     * True when the connector reports that it no longer tracks (or never tracked) the operation —
     * the upstream identity/handle is gone. Cancel treats this as a soft success (NOT_TRACKED);
     * the poll listener treats it as a terminal poll error (no point retrying).
     */
    public static boolean isOperationNotTracked(ErrorCode code) {
        return code == ErrorCode.OPERATION_NOT_TRACKED
                || code == ErrorCode.REGISTRATION_NOT_FOUND;
    }
}
