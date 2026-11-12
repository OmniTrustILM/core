package com.otilm.core.certificate.type;

import com.otilm.api.exception.ValidationException;

/** A certificate type handler could not do what it was asked; the message is meant for the client. */
public class CertificateTypeHandlerException extends ValidationException {

    public CertificateTypeHandlerException(String message) {
        super(message);
    }
}
