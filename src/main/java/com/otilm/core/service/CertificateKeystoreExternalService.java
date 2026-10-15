package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.CertificateKeystoreRequestDto;
import com.otilm.core.model.certificate.DownloadedKeystore;
import com.otilm.core.security.authz.SecuredUUID;

/** Downloads a certificate with its private key, protected under a passphrase the caller chooses. */
public interface CertificateKeystoreExternalService {

    /**
     * The certificate, its chain and its private key as one PKCS#12 file. The key is exported through its connector and
     * never opened by the platform.
     *
     * @param uuid UUID of the certificate
     * @param request the passphrase that protects the file, and the export attributes
     * @return the file and its name
     * @throws NotFoundException if the certificate does not exist, or its key holds no private key
     */
    DownloadedKeystore downloadKeystore(SecuredUUID uuid, CertificateKeystoreRequestDto request)
            throws NotFoundException, ConnectorException;
}
