package com.otilm.core.model.signing;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.oid.SystemOid;

import java.util.List;
import java.util.UUID;

/**
 * Test builder for {@link SigningCertificate} snapshots.
 * Defaults produce a certificate valid for non-qualified timestamping (mirrors {@code CertificateBuilder}).
 */
public final class SigningCertificateBuilder {

    private UUID uuid = UUID.randomUUID();
    private String commonName = "ts-signer";
    private boolean archived = false;
    private CertificateState state = CertificateState.ISSUED;
    private CertificateValidationStatus validationStatus = CertificateValidationStatus.VALID;
    private List<String> extendedKeyUsageOids = List.of(SystemOid.TIME_STAMPING.getOid());
    private Boolean extendedKeyUsageCritical = Boolean.TRUE;
    private Boolean qcCompliance = null;
    private UUID keyUuid = UUID.randomUUID();
    private UUID tokenInstanceReferenceUuid = UUID.randomUUID();
    private UUID tokenProfileUuid = UUID.randomUUID();
    private List<UUID> keyItemUuids = List.of();

    public static SigningCertificateBuilder aSigningCertificate() {
        return new SigningCertificateBuilder();
    }

    /** Returns a minimal valid certificate snapshot for non-qualified timestamping. */
    public static SigningCertificate valid() {
        return aSigningCertificate().build();
    }

    public SigningCertificateBuilder uuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public SigningCertificateBuilder commonName(String commonName) {
        this.commonName = commonName;
        return this;
    }

    public SigningCertificateBuilder archived(boolean archived) {
        this.archived = archived;
        return this;
    }

    public SigningCertificateBuilder state(CertificateState state) {
        this.state = state;
        return this;
    }

    public SigningCertificateBuilder validationStatus(CertificateValidationStatus validationStatus) {
        this.validationStatus = validationStatus;
        return this;
    }

    public SigningCertificateBuilder extendedKeyUsageOids(List<String> extendedKeyUsageOids) {
        this.extendedKeyUsageOids = extendedKeyUsageOids;
        return this;
    }

    public SigningCertificateBuilder extendedKeyUsageCritical(Boolean extendedKeyUsageCritical) {
        this.extendedKeyUsageCritical = extendedKeyUsageCritical;
        return this;
    }

    public SigningCertificateBuilder qcCompliance(Boolean qcCompliance) {
        this.qcCompliance = qcCompliance;
        return this;
    }

    public SigningCertificateBuilder keyUuid(UUID keyUuid) {
        this.keyUuid = keyUuid;
        return this;
    }

    public SigningCertificateBuilder tokenInstanceReferenceUuid(UUID tokenInstanceReferenceUuid) {
        this.tokenInstanceReferenceUuid = tokenInstanceReferenceUuid;
        return this;
    }

    public SigningCertificateBuilder tokenProfileUuid(UUID tokenProfileUuid) {
        this.tokenProfileUuid = tokenProfileUuid;
        return this;
    }

    public SigningCertificateBuilder keyItemUuids(List<UUID> keyItemUuids) {
        this.keyItemUuids = keyItemUuids;
        return this;
    }

    /** Detaches the certificate from any cryptographic key (no key UUID, token profile, or items). */
    public SigningCertificateBuilder withoutKey() {
        this.keyUuid = null;
        this.tokenInstanceReferenceUuid = null;
        this.tokenProfileUuid = null;
        this.keyItemUuids = List.of();
        return this;
    }

    public SigningCertificate build() {
        return new SigningCertificate(
                uuid,
                commonName,
                archived,
                state,
                validationStatus,
                List.copyOf(extendedKeyUsageOids),
                extendedKeyUsageCritical,
                qcCompliance,
                keyUuid,
                tokenInstanceReferenceUuid,
                tokenProfileUuid,
                List.copyOf(keyItemUuids)
        );
    }
}
