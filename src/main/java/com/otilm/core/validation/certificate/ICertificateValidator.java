package com.otilm.core.validation.certificate;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;

import java.security.cert.CertificateException;
import java.util.List;

public interface ICertificateValidator {

    /**
     * Validates a certificate along the chain the caller built for it and stores the result for every certificate in
     * the chain; an issued certificate that OCSP or a CRL reports as revoked is marked revoked.
     *
     * @param certificateChain the certificate under validation first, then each issuer in turn; validate along this
     * chain, not along the certificates' issuer links
     * @param isCompleteChain whether the chain ends in a self-signed certificate
     * @return the validation status of the first certificate in the chain
     */
    CertificateValidationStatus validateCertificate(List<Certificate> certificateChain, boolean isCompleteChain)
            throws CertificateException;
}
