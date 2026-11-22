package com.otilm.core.exception;

import com.otilm.api.exception.PlatformException;

/**
 * A conditional request whose precondition no longer holds. The message is authored by the platform and safe to expose;
 * the API answers it with 412.
 */
public class PreconditionFailedException extends RuntimeException implements PlatformException {
    public PreconditionFailedException(String message) {
        super(message);
    }
}
