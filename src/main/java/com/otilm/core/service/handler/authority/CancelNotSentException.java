package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.PlatformException;

/**
 * A cancel that failed before its request reached the connector, as when a stored attribute or the connector could not
 * be resolved. The connector has said nothing about the operation, so its cause is no answer of the connector.
 */
public class CancelNotSentException extends RuntimeException implements PlatformException {

    public CancelNotSentException(Exception cause) {
        super("The cancel request could not be prepared for the connector", cause);
    }

    /** The failure that kept the request from being sent. */
    public Exception reason() {
        return (Exception) getCause();
    }
}
