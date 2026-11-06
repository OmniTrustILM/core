package com.otilm.core.dao.entity;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.Hibernate;
import org.hibernate.annotations.DynamicUpdate;

@Getter
@Setter
@ToString(callSuper = true)
@Entity
@DiscriminatorValue("X509")
// Dynamic update is not inherited by a subclass; without it every column is written back, including the state a
// concurrent revocation committed after this entity was read. The reason is spelled out on Certificate.
@DynamicUpdate
public class X509CertificateEntity extends Certificate {

    public X509CertificateEntity() {
        setCertificateType(CertificateType.X509);
    }

    /**
     * Views a certificate as X.509, looking through a lazy proxy of the base type. Null when it is not X.509.
     */
    public static X509CertificateEntity fromOrNull(Certificate certificate) {
        return Hibernate.unproxy(certificate) instanceof X509CertificateEntity x509 ? x509 : null;
    }

    /**
     * The subject DN of an X.509 certificate, or null for a certificate of another type. For log context that must not
     * turn into a refusal.
     */
    public static String subjectDnOrNull(Certificate certificate) {
        X509CertificateEntity x509 = fromOrNull(certificate);
        return x509 == null ? null : x509.getSubjectDn();
    }

    /**
     * Views a certificate as X.509 for an operation that exists only for that type.
     *
     * @throws ValidationException if the certificate is of another type
     */
    public static X509CertificateEntity from(Certificate certificate) {
        X509CertificateEntity x509 = fromOrNull(certificate);
        if (x509 == null) {
            throw new ValidationException("The operation is available only for X.509 certificates, certificate "
                    + certificate.getUuid() + " is of type " + certificate.getCertificateType().getLabel() + ".");
        }
        return x509;
    }

    @Column(name = "issuer_dn")
    private String issuerDn;

    @Column(name = "issuer_dn_normalized")
    private String issuerDnNormalized;

    @Column(name = "subject_dn")
    private String subjectDn;

    @Column(name = "subject_dn_normalized")
    private String subjectDnNormalized;

    @Column(name = "extended_key_usage")
    private String extendedKeyUsage;

    @Column(name = "extended_key_usage_critical")
    private Boolean extendedKeyUsageCritical;

    @Column(name = "qc_compliance")
    private Boolean qcCompliance;

    @Column(name = "qc_sscd")
    private Boolean qcSscd;

    @Column(name = "qc_type")
    private String qcType;

    @Column(name = "qc_cc_legislation")
    private String qcCcLegislation;

    @Column(name = "key_usage", nullable = false)
    private int keyUsage;

    @Column(name = "subject_alternative_names")
    private String subjectAlternativeNames;

    @Column(name = "issuer_serial_number")
    private String issuerSerialNumber;

    @Column(name = "trusted_ca")
    private Boolean trustedCa;

    @Column(name = "alt_public_key_algorithm")
    private String altPublicKeyAlgorithm;

    @Column(name = "alt_key_size")
    private Integer altKeySize;

    @Column(name = "alt_key_fingerprint")
    private String altKeyFingerprint;

    @Column(name = "alt_signature_algorithm")
    private String altSignatureAlgorithm;

    @Column(name = "hybrid_certificate", nullable = false)
    private boolean hybridCertificate = false;

    public void setTrustedCa(boolean trustedCa) {
        this.trustedCa = trustedCa;
    }

    public Set<CertificateKeyUsage> getKeyUsage() {
        return CertificateKeyUsage.convertBitMaskToSet(keyUsage);
    }

    public int getKeyUsageBitMask() {
        return keyUsage;
    }

    public void setUsage(List<CertificateKeyUsage> usage) {
        this.keyUsage = BitMaskEnum
                .convertSetToBitMask(
                        usage.isEmpty() ? EnumSet.noneOf(CertificateKeyUsage.class) : EnumSet.copyOf(usage));
    }

    @Override
    public X509CertificateRequestEntity prepareCertificateRequest(
            final CertificateRequestFormat certificateRequestFormat) {
        final X509CertificateRequestEntity newCertificateRequestEntity = new X509CertificateRequestEntity();
        newCertificateRequestEntity.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        newCertificateRequestEntity.setKeyUsage(this.keyUsage);
        newCertificateRequestEntity.setCommonName(getCommonName());
        newCertificateRequestEntity.setPublicKeyAlgorithm(getPublicKeyAlgorithm());
        newCertificateRequestEntity.setSubjectAlternativeNames(this.subjectAlternativeNames);
        newCertificateRequestEntity.setSubjectDn(this.subjectDn);
        newCertificateRequestEntity.setCertificateRequestFormat(certificateRequestFormat);
        return newCertificateRequestEntity;
    }

    @Override
    public String toStringShort() {
        return String
                .format("Certificate(UUID=%s, subjectDn=%s, issuerDn=%s, serialNumber=%s, fingerprint=%s)", getUuid(),
                        subjectDn, issuerDn, getSerialNumber(), getFingerprint());
    }
}
