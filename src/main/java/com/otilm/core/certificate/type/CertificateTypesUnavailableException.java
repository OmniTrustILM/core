package com.otilm.core.certificate.type;

import com.otilm.api.exception.PlatformException;
import com.otilm.core.dao.entity.Connector;

/**
 * The connector of an RA profile's authority failed or gave an answer that cannot be used when asked which certificate
 * types the authority issues.
 */
public class CertificateTypesUnavailableException extends RuntimeException implements PlatformException {

    public CertificateTypesUnavailableException(String raProfileName, Connector connector, Exception cause) {
        super("The certificate types the authority of RA profile " + raProfileName
                + " issues could not be read from connector name=" + connector.getName() + ", uuid="
                + connector.getUuid(), cause);
    }
}
