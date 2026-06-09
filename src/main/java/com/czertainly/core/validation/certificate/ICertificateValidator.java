package com.czertainly.core.validation.certificate;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.entity.Certificate;

import java.security.cert.CertificateException;

public interface ICertificateValidator {
    CertificateValidationStatus validateCertificate(Certificate certificate, boolean isCompleteChain) throws CertificateException;
}
