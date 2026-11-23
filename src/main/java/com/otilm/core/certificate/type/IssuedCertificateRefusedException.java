package com.otilm.core.certificate.type;

import com.otilm.api.exception.PlatformException;

/**
 * What an authority returned for a requested certificate cannot be stored as that certificate. The message is written
 * by the platform and holds no text of the authority, so it is meant for the client and for the certificate history.
 */
public class IssuedCertificateRefusedException extends RuntimeException implements PlatformException {

    public IssuedCertificateRefusedException(String message) {
        super(message);
    }
}
