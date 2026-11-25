package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.PlatformException;

/** A renewal a handler could not start; its message is recorded in the certificate and trigger history. */
public class AutoRenewalException extends Exception implements PlatformException {

    public AutoRenewalException(String message) {
        super(message);
    }

    public AutoRenewalException(String message, Throwable cause) {
        super(message, cause);
    }
}
