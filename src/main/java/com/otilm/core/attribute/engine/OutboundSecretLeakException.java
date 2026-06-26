package com.otilm.core.attribute.engine;

/**
 * Raised by {@link OutboundSecretContainment} when an FE-bound callback response would carry secret material the
 * expander materialized server-side — either by echoing an expanded secret value or by structurally containing a
 * secret-bearing content shape. The dispatch arm (#1621) maps this to a connector contract violation
 * (502 {@code CONNECTOR_PROTOCOL_VIOLATION}) and does not forward the response.
 */
public class OutboundSecretLeakException extends RuntimeException {

    public OutboundSecretLeakException(String message) {
        super(message);
    }
}
