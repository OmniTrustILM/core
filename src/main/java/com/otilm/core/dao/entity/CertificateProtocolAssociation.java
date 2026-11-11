package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import jakarta.persistence.Column;
import jakarta.persistence.ConstraintMode;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JoinFormula;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.proxy.HibernateProxy;

/**
 * The protocol a certificate was issued through. All protocols keep their profile in {@code protocol_profile_uuid} and
 * Hibernate ignores {@code @SQLRestriction} on a to-one association, so each profile is a formula that yields the
 * column only for its own protocol and only while the profile exists; a join column would reference a row the profile's
 * table does not hold.
 */
@Entity
@Getter
@Setter
// A certificate has at most one protocol association: Certificate.protocolAssociation maps it one-to-one.
@Table(name = "certificate_protocol_association",
        uniqueConstraints = @UniqueConstraint(name = "uq_certificate_protocol_association_certificate",
                columnNames = "certificate_uuid"))
public class CertificateProtocolAssociation extends UniquelyIdentified implements Serializable {

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_uuid", insertable = false, updatable = false)
    private Certificate certificate;

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    @Column(name = "protocol", nullable = false)
    @Enumerated(EnumType.STRING)
    private CertificateProtocol protocol;

    @Column(name = "protocol_profile_uuid")
    private UUID protocolProfileUuid;

    @Column(name = "additional_protocol_uuid")
    private UUID additionalProtocolUuid;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinFormula("CASE WHEN protocol = 'ACME' AND EXISTS (SELECT 1 FROM {h-schema}acme_profile p"
            + " WHERE p.uuid = protocol_profile_uuid) THEN protocol_profile_uuid END")
    private AcmeProfile acmeProfile;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinFormula("CASE WHEN protocol = 'SCEP' AND EXISTS (SELECT 1 FROM {h-schema}scep_profile p"
            + " WHERE p.uuid = protocol_profile_uuid) THEN protocol_profile_uuid END")
    private ScepProfile scepProfile;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinFormula("CASE WHEN protocol = 'CMP' AND EXISTS (SELECT 1 FROM {h-schema}cmp_profile p"
            + " WHERE p.uuid = protocol_profile_uuid) THEN protocol_profile_uuid END")
    private CmpProfile cmpProfile;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "additional_protocol_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    @SQLRestriction("protocol = 'ACME'")
    private AcmeAccount acmeAccount;

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
        if (certificate != null) {
            certificateUuid = certificate.getUuid();
        }
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        CertificateProtocolAssociation that = (CertificateProtocolAssociation) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }

}
