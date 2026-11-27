package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateType;
import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.Hibernate;

@Getter
@Setter
@ToString(callSuper = true)
@Entity
@DiscriminatorValue("CVC")
public class CvcCertificateRequestEntity extends CertificateRequestEntity {

    public CvcCertificateRequestEntity() {
        setCertificateType(CertificateType.CVC);
    }

    /**
     * Views a certificate request as CVC, looking through a lazy proxy of the base type. Null when it is not CVC.
     */
    public static CvcCertificateRequestEntity fromOrNull(CertificateRequestEntity request) {
        return Hibernate.unproxy(request) instanceof CvcCertificateRequestEntity cvc ? cvc : null;
    }

    @Column(name = "holder_reference")
    private String holderReference;

    @Column(name = "authority_reference")
    private String authorityReference;

    @Column(name = "authenticated_by")
    private String authenticatedBy;
}
