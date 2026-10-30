package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.PlatformException;

/**
 * A reported key that cannot be identified. Platform shaped because its message is written for the operator who reads
 * it, and reaches them through {@code discovery_item.processed_error}.
 */
public class UnusableDiscoveredKeyException extends RuntimeException implements PlatformException {

    public UnusableDiscoveredKeyException(String message) {
        super(message);
    }

    public UnusableDiscoveredKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
