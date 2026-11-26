package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateType;
import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.Hibernate;
import org.hibernate.annotations.ColumnDefault;

@Getter
@Setter
@ToString(callSuper = true)
@Entity
@DiscriminatorValue("X509")
public class X509CertificateRequestEntity extends CertificateRequestEntity {

    public X509CertificateRequestEntity() {
        setCertificateType(CertificateType.X509);
    }

    /**
     * Views a certificate request as X.509, looking through a lazy proxy of the base type. Null when it is not X.509.
     */
    public static X509CertificateRequestEntity fromOrNull(CertificateRequestEntity request) {
        return Hibernate.unproxy(request) instanceof X509CertificateRequestEntity x509 ? x509 : null;
    }

    @Column(name = "alt_public_key_algorithm")
    private String altPublicKeyAlgorithm;

    @Column(name = "alt_signature_algorithm")
    private String altSignatureAlgorithm;

    @Column(name = "subject_dn")
    private String subjectDn;

    @Column(name = "subject_alternative_names")
    private String subjectAlternativeNames;

    // The default lets a request of another certificate type, which has no key usage, be stored.
    @ColumnDefault("0")
    @Column(name = "key_usage", nullable = false)
    private int keyUsage;
}
