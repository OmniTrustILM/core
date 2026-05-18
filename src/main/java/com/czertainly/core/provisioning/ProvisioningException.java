package com.czertainly.core.provisioning;

import com.czertainly.api.exception.PlatformException;

/**
 * Exception thrown when provisioning operations fail.
 */
public class ProvisioningException extends RuntimeException implements PlatformException {

    public ProvisioningException(String message) {
        super(message);
    }

    public ProvisioningException(String message, Throwable cause) {
        super(message, cause);
    }
}