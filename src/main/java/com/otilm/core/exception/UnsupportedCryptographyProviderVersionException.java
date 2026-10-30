package com.otilm.core.exception;

import com.otilm.api.exception.PlatformException;

/** Raised when Core cannot select a supported cryptography-provider protocol for a token connector. */
public class UnsupportedCryptographyProviderVersionException extends RuntimeException implements PlatformException {

    public UnsupportedCryptographyProviderVersionException(String message) {
        super(message);
    }
}
