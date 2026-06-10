package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "crl_entry")
public class CrlEntry implements Serializable {

    @EmbeddedId
    private CrlEntryId id = new CrlEntryId();

    @ManyToOne
    @MapsId("crlUuid")
    private Crl crl;

    @Column(name = "revocation_date", nullable = false)
    private Date revocationDate;

    @Column(name = "revocation_reason", nullable = false)
    @Enumerated(EnumType.STRING)
    private CertificateRevocationReason revocationReason;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CrlEntry crlEntry = (CrlEntry) o;
        return getId() != null && Objects.equals(getId(), crlEntry.getId());
    }

    @Override
    public final int hashCode() {
        return Objects.hash(id);
    }
}
