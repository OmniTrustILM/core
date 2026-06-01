package com.czertainly.core.model.signing;

import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;

import java.util.List;
import java.util.UUID;

/**
 * Immutable, internal-only snapshot of the certificate data for digital signing.
 */
public record SigningCertificate(
        UUID uuid,
        String commonName,
        // certificate-level acceptability inputs
        boolean archived,
        CertificateState state,
        CertificateValidationStatus validationStatus,
        List<String> extendedKeyUsageOids,
        Boolean extendedKeyUsageCritical,
        Boolean qcCompliance,
        // structural references (key-level), not key-item material
        UUID keyUuid,
        UUID tokenInstanceReferenceUuid,
        UUID tokenProfileUuid,
        List<UUID> keyItemUuids
) {}
