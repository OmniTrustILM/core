package com.czertainly.core.dao.entity.cmp;

import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.UniquelyIdentified;
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
@Table(name = "cmp_transaction")
public class CmpTransaction extends UniquelyIdentified {

    @Setter
    @Getter
    @Column(name="transaction_id")
    private String transactionId;

    @Setter
    @Getter
    @Column(name = "certificate_uuid")
    private UUID certificateUuid;

    @Setter
    @Getter
    @Column(name = "cmp_profile_uuid")
    private UUID cmpProfileUuid;

    @Setter
    @Getter
    @Column(name = "state")
    @Enumerated(EnumType.STRING)
    private CmpTransactionState state;

    @Setter
    @Getter
    @Column(name = "custom_reason")
    private String customReason;

    /**
     * BouncyCastle {@code PKIBody.TYPE_*} integer of the original request that opened this
     * transaction (e.g. {@code TYPE_INIT_REQ=0}, {@code TYPE_CERT_REQ=2},
     * {@code TYPE_KEY_UPDATE_REQ=7}, {@code TYPE_REVOCATION_REQ=11}). Used by the pollReq
     * handler to build the right response body type when the in-flight operation eventually
     * completes. Nullable for transactions created before this column was added.
     */
    @Setter
    @Getter
    @Column(name = "original_request_body_type")
    private Integer originalRequestBodyType;

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "cmp_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CmpProfile cmpProfile;
    public CmpProfile getCmpProfile() {
        return cmpProfile;
    }
    public void setCmpProfile(CmpProfile cmpProfile) {
        this.cmpProfile = cmpProfile;
        if(cmpProfile != null) this.cmpProfileUuid = cmpProfile.getUuid();
    }

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "certificate_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Certificate certificate;
    public Certificate getCertificate() {
        return certificate;
    }
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
        if(certificate != null) certificateUuid = certificate.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CmpTransaction that = (CmpTransaction) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
