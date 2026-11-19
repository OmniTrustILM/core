package com.otilm.core.validation.certificate;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;

import java.security.cert.CertificateException;
import java.util.List;

public interface ICertificateValidator {

    /**
     * Validates the chain's first certificate and stores a result for every certificate in the chain, marking an issued
     * certificate revoked when OCSP or a CRL reports it.
     *
     * @param certificateChain the certificate to validate, then each issuer in turn; follow this chain, not the
     * certificates' issuer links
     * @param isCompleteChain whether the chain ends in a self-signed certificate
     * @return the validation status of the first certificate in the chain
     */
    CertificateValidationStatus validateCertificate(List<Certificate> certificateChain, boolean isCompleteChain)
            throws CertificateException;
}
