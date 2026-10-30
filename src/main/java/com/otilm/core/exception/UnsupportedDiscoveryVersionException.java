package com.otilm.core.exception;

import com.otilm.api.exception.PlatformException;

/**
 * Thrown by DiscoveryProviderAdapterFactory when no adapter is registered for the discovery connector interface version
 * a run is associated with.
 */
public class UnsupportedDiscoveryVersionException extends RuntimeException implements PlatformException {
    public UnsupportedDiscoveryVersionException(String message) {
        super(message);
    }
}
