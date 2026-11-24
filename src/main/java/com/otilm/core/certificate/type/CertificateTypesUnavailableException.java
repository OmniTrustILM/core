package com.otilm.core.certificate.type;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.dao.entity.Connector;

/**
 * The connector of an RA profile's authority failed or gave an answer that cannot be used when asked which certificate
 * types the authority issues, so nothing was sent to it.
 */
public class CertificateTypesUnavailableException extends RuntimeException implements PlatformException {

    public CertificateTypesUnavailableException(String raProfileName, Connector connector, ConnectorException cause) {
        super("The certificate types the authority of RA profile " + raProfileName
                + " issues could not be read from connector name=" + connector.getName() + ", uuid="
                + connector.getUuid(), cause);
    }
}
