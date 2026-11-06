package com.otilm.core.dao.entity;

import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.model.compliance.ComplianceResultDto;
import com.otilm.core.util.CertificateUtil;
import jakarta.persistence.Column;
import jakarta.persistence.ConstraintMode;
import jakarta.persistence.DiscriminatorColumn;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Inheritance;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "certificate_request")
@Inheritance
@DiscriminatorColumn(name = "certificate_type")
public abstract class CertificateRequestEntity extends UniquelyIdentifiedAndAudited implements ComplianceSubject {

    @Column(name = "certificate_type", nullable = false, insertable = false, updatable = false)
    @Setter(AccessLevel.PROTECTED)
    @Enumerated(EnumType.STRING)
    private CertificateType certificateType;

    @Column(name = "certificate_request_format", nullable = false)
    @Enumerated(EnumType.STRING)
    private CertificateRequestFormat certificateRequestFormat;

    @Column(name = "public_key_algorithm")
    private String publicKeyAlgorithm;

    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;

    @Column(name = "fingerprint", nullable = false)
    private String fingerprint;

    @Column(name = "content", length = Integer.MAX_VALUE, nullable = false)
    private String content;

    @Column(name = "common_name")
    private String commonName;

    @Column(name = "compliance_result", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ComplianceResultDto complianceResult;

    @Column(name = "compliance_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private ComplianceStatus complianceStatus = ComplianceStatus.NOT_CHECKED;

    // The migrated schema carries no foreign key on either key column: deleting a key leaves its requests in place.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    @ToString.Exclude
    private CryptographicKey key;

    @Column(name = "key_uuid")
    private UUID keyUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alt_key_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    @ToString.Exclude
    private CryptographicKey altKey;

    @Column(name = "alt_key_uuid")
    private UUID altKeyUuid;

    public void setContent(String content) throws NoSuchAlgorithmException {
        this.content = content;
        if (this.fingerprint == null) {
            final byte[] contentDecoded = Base64.getDecoder().decode(content);
            this.fingerprint = CertificateUtil.getThumbprint(contentDecoded);
        }
    }

    public byte[] getContentDecoded() {
        return Base64.getDecoder().decode(content);
    }

    @Override
    public IPlatformEnum getType() {
        return certificateType;
    }

    @Override
    public IPlatformEnum getFormat() {
        return certificateRequestFormat;
    }

    @Override
    public String getContentData() {
        return this.content;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        if (!(o instanceof CertificateRequestEntity that)) {
            return false;
        }
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return CertificateRequestEntity.class.hashCode();
    }
}
