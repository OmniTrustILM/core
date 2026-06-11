package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "ra_profile_protocol_attribute")
public class RaProfileProtocolAttribute extends UniquelyIdentified {

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    /**
     * ACME related attributes
     */
    @Column(name = "acme_issue_certificate_attributes", length = Integer.MAX_VALUE)
    private String acmeIssueCertificateAttributes;

    @Column(name = "acme_revoke_certificate_attributes", length = Integer.MAX_VALUE)
    private String acmeRevokeCertificateAttributes;

    /**
     * SCEP related attributes
     */
    @Column(name = "scep_issue_certificate_attributes", length = Integer.MAX_VALUE)
    private String scepIssueCertificateAttributes;

    /**
     * CMP protocol related attributes
     */
    @Column(name = "cmp_issue_certificate_attributes", length = Integer.MAX_VALUE)
    private String cmpIssueCertificateAttributes;

    @Column(name = "cmp_revoke_certificate_attributes", length = Integer.MAX_VALUE)
    private String cmpRevokeCertificateAttributes;

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if(raProfile != null) raProfileUuid = raProfile.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        RaProfileProtocolAttribute that = (RaProfileProtocolAttribute) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
