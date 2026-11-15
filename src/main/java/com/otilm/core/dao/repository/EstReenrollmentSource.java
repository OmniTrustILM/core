package com.otilm.core.dao.repository;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.enums.CertificateProtocol;
import java.util.Date;
import java.util.UUID;

/**
 * The certificate an EST client presents to renew, as far as deciding whether it may renew needs it. A projection, so
 * the lookup runs without an open persistence context and loads neither the certificate content nor its associations.
 * The protocol and its profile are {@code null} for a certificate that no protocol issued.
 */
public interface EstReenrollmentSource {

    UUID getUuid();

    CertificateState getState();

    Boolean getArchived();

    Date getNotBefore();

    Date getNotAfter();

    CertificateValidationStatus getValidationStatus();

    UUID getRaProfileUuid();

    String getSubjectDn();

    String getSubjectAlternativeNames();

    String getAltKeyFingerprint();

    CertificateProtocol getProtocol();

    UUID getProtocolProfileUuid();
}
