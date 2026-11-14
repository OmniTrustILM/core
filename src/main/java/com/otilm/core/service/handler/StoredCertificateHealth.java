package com.otilm.core.service.handler;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationCheck;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public record StoredCertificateHealth(UUID certificateUuid, UUID raProfileUuid, String commonName, String serialNumber,
        String issuerCommonName, String fingerprint, Instant notBefore, Instant notAfter, CertificateState state,
        CertificateValidationStatus validationStatus, OffsetDateTime validationTimestamp,
        Map<CertificateValidationCheck, CertificateValidationStatus> checks, Evidence evidence) {
    public StoredCertificateHealth {
        checks = Map.copyOf(checks);
    }

    public enum Evidence {
        PRESENT,
        MISSING,
        MALFORMED
    }
}
