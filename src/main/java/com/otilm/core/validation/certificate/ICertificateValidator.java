package com.otilm.core.validation.certificate;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;

import java.security.cert.CertificateException;
import java.util.List;

public interface ICertificateValidator {

    /**
     * Validates a certificate along the chain the caller built for it.
     *
     * @param certificateChain the certificate under validation first, then each issuer in turn; the validator does not
     * follow issuer links of its own, so the chain and {@code isCompleteChain} describe the same read of the inventory
     * @param isCompleteChain whether the chain ends in a self-signed certificate
     * @return the validation status of the first certificate in the chain
     */
    CertificateValidationStatus validateCertificate(List<Certificate> certificateChain, boolean isCompleteChain)
            throws CertificateException;
}
