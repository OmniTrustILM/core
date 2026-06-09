package com.czertainly.core.exception;

import com.otilm.api.exception.ConnectorException;

/**
 * Thrown by the v3 authority adapter when the connector has accepted the operation (200/202)
 * but a subsequent local processing step failed. Per the state-divergence pattern documented
 * in the core CLAUDE.md, callers MUST NOT roll back certificate state on this exception —
 * the external commitment must be preserved.
 */
public class ConnectorAcceptedButLocalFailureException extends ConnectorException {
    public ConnectorAcceptedButLocalFailureException(String message, Throwable cause) {
        super(message, cause);
    }
}
