package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.UUID;

/**
 * Platform-owned, RA-Profile-scoped static request-attribute set.
 *
 * <p>Mirrors {@link RaProfileProtocolAttribute}'s serialized pattern but is kept separate because request attributes are
 * <em>not</em> protocol-specific.
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "ra_profile_request_attribute")
public class RaProfileCertificateRequestAttribute extends UniquelyIdentified {

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    /**
     * Serialized JSON {@code List<BaseAttribute>} of the static request-attribute definitions.
     */
    @Column(name = "request_attributes", length = Integer.MAX_VALUE)
    private String requestAttributes;

    /**
     * How the static set combines with a connector-supplied set; {@code null} is treated as
     * {@link AttributeSetMergeMode#MERGE} by the resolver.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "merge_mode")
    private AttributeSetMergeMode mergeMode;

    /**
     * Whether an external CSR violating the resolved set is rejected (true) or accepted with warnings (false);
     * {@code null} inherits the platform default; the flag is consumed when an external CSR is validated
     * against the resolved request-attribute set.
     */
    @Column(name = "external_csr_validation_strict")
    private Boolean externalCsrValidationStrict;

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if (raProfile != null) raProfileUuid = raProfile.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        RaProfileCertificateRequestAttribute that = (RaProfileCertificateRequestAttribute) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
