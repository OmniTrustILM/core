package com.otilm.core.attribute.engine;

import com.otilm.api.exception.PlatformException;

/**
 * Raised by {@link OutboundSecretContainment} when an FE-bound callback response would carry secret material the
 * expander materialized server-side — either by echoing an expanded secret value or by structurally containing a
 * secret-bearing content shape. The NG dispatcher throws this before forwarding, so the offending response is
 * never returned to the FE (fail-closed). The message is a fixed, secret-free string. Mapping it to a dedicated
 * connector-contract HTTP status is a follow-up; today it propagates as a generic server error.
 */
public class OutboundSecretLeakException extends RuntimeException implements PlatformException {

    public OutboundSecretLeakException(String message) {
        super(message);
    }
}
