package com.otilm.core.dao.repository;

import com.otilm.api.model.core.certificate.CertificateState;
import java.util.Date;
import java.util.UUID;

/**
 * The certificate an EST request created, as far as answering a retry of that request needs it. A projection, so the
 * lookup runs without an open persistence context and loads neither the certificate content nor its associations.
 */
public interface EstRequestedCertificate {

    UUID getUuid();

    CertificateState getState();

    Date getNotAfter();

    /** SHA-256 of the request in lower-case hexadecimal, {@code null} for a certificate that has no request. */
    String getRequestFingerprint();
}
