package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "crl", uniqueConstraints = {@UniqueConstraint(columnNames = {"issuerDn", "serialNumber"})})
public class Crl extends UniquelyIdentified {

    @Column(name = "ca_certificate_uuid")
    private UUID caCertificateUuid;

    @Column(name = "issuer_dn", nullable = false)
    private String issuerDn;

    @Column(name = "serial_number", nullable = false)
    private String serialNumber;

    @Column(name = "crl_issuer_dn", nullable = false)
    private String crlIssuerDn;

    @Column(name = "crl_number", nullable = false)
    private String crlNumber;

    @Column(name = "next_update", nullable = false)
    private Date nextUpdate;

    @Column(name = "crl_number_delta")
    private String crlNumberDelta;

    @Column(name = "next_update_delta")
    private Date nextUpdateDelta;

    @Column(name = "last_revocation_date")
    private Date lastRevocationDate;

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        Crl crl = (Crl) o;
        return getUuid() != null && Objects.equals(getUuid(), crl.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
