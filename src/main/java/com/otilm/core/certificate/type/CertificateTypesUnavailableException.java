package com.otilm.core.certificate.type;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.PlatformException;

/** The authority of an RA profile could not say which certificate types it issues, so nothing was sent to it. */
public class CertificateTypesUnavailableException extends RuntimeException implements PlatformException {

    public CertificateTypesUnavailableException(String raProfileName, ConnectorException cause) {
        super("The authority of RA profile " + raProfileName + " could not be asked which certificate types it issues",
                cause);
    }
}
