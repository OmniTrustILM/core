package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.Hibernate;
import org.hibernate.annotations.DynamicUpdate;

/**
 * A card verifiable certificate. Its validity has date precision: the shared validity columns hold the start of the
 * effective day and the start of the day after the expiration date, both in UTC, so the expiration date is inclusive.
 * Holder references are not unique: a CVCA link certificate has the holder reference and the public key of the new CVCA
 * certificate it links to.
 */
@Getter
@Setter
@ToString(callSuper = true)
@Entity
@DiscriminatorValue("CVC")
// Dynamic update is not inherited by a subclass; the reason is spelled out on Certificate.
@DynamicUpdate
public class CvcCertificateEntity extends Certificate {

    private static final Duration ONE_DAY = Duration.ofDays(1);

    public CvcCertificateEntity() {
        setCertificateType(CertificateType.CVC);
    }

    /**
     * Views a certificate as CVC, looking through a lazy proxy of the base type. Null when it is not CVC.
     */
    public static CvcCertificateEntity fromOrNull(Certificate certificate) {
        return Hibernate.unproxy(certificate) instanceof CvcCertificateEntity cvc ? cvc : null;
    }

    @Column(name = "holder_reference")
    private String holderReference;

    @Column(name = "authority_reference")
    private String authorityReference;

    @Column(name = "role")
    private String role;

    @Column(name = "terminal_type")
    private String terminalType;

    @Column(name = "access_rights")
    private String accessRights;

    /** The first day the certificate is valid, or null when it has no validity yet. */
    public LocalDate getEffectiveDate() {
        return getNotBefore() == null ? null : getNotBefore().toInstant().atZone(ZoneOffset.UTC).toLocalDate();
    }

    /** The last day the certificate is valid, or null when it has no validity yet. */
    public LocalDate getExpirationDate() {
        return getNotAfter() == null
                ? null
                : getNotAfter().toInstant().minus(ONE_DAY).atZone(ZoneOffset.UTC).toLocalDate();
    }

    @Override
    public CvcCertificateRequestEntity prepareCertificateRequest(CertificateRequestFormat certificateRequestFormat) {
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        request.setPublicKeyAlgorithm(getPublicKeyAlgorithm());
        request.setHolderReference(holderReference);
        request.setCertificateRequestFormat(certificateRequestFormat);
        return request;
    }

    @Override
    public String toStringShort() {
        return String
                .format("Certificate(UUID=%s, holderReference=%s, authorityReference=%s, fingerprint=%s)", getUuid(),
                        holderReference, authorityReference, getFingerprint());
    }
}
