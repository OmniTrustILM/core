package com.czertainly.core.provisioning;

/**
 * Exception thrown when provisioning operations fail.
 */
public class ProvisioningException extends RuntimeException {

    public ProvisioningException(String message) {
        super(message);
    }

    public ProvisioningException(String message, Throwable cause) {
        super(message, cause);
    }
}