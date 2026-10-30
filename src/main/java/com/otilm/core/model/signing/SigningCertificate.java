package com.otilm.core.model.signing;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * Immutable, internal-only snapshot of the certificate data for digital signing.
 */
public record SigningCertificate(UUID uuid, String commonName, boolean archived, CertificateState state,
        CertificateValidationStatus validationStatus, List<String> extendedKeyUsageOids,
        Boolean extendedKeyUsageCritical, Boolean qcCompliance, UUID keyUuid, UUID tokenInstanceReferenceUuid,
        UUID tokenProfileUuid, List<UUID> keyItemUuids, int keyUsageBitMask, CertificateSubjectType subjectType) {

    /** Order of {@link #keyItemUuids}; the signer uses the first private item in it. */
    public static final Comparator<UUID> KEY_ITEM_ORDER = Comparator.naturalOrder();
}
