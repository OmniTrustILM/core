package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

/**
 * The automatic renewal of a certificate in one key-generating location: the successor it started, its failed attempts
 * and backoff, and when it completed. {@code startedAt} marks a renewal call in progress. A window change clears the
 * failure counters of rows not yet completed.
 */
@Entity
@Getter
@Setter
@ToString
@Table(name = "certificate_renewal_location",
        uniqueConstraints = @UniqueConstraint(name = "uq_certificate_renewal_location",
                columnNames = {"certificate_uuid", "location_uuid"}))
public class CertificateRenewalLocation extends UniquelyIdentified implements Serializable {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Certificate certificate;

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    @Column(name = "location_uuid", nullable = false)
    private UUID locationUuid;

    @Column(name = "successor_uuid")
    private UUID successorUuid;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "attempt", nullable = false, columnDefinition = "integer not null default 0")
    private int attempt;

    @Column(name = "not_before")
    private Instant notBefore;

    @Column(name = "completed_at")
    private Instant completedAt;

    /** The user the firing that started {@code successorUuid} acted as. */
    @Column(name = "owner_uuid")
    private UUID ownerUuid;

    /** The trigger history of the firing that started {@code successorUuid}, when a trigger started it. */
    @Column(name = "trigger_history_uuid")
    private UUID triggerHistoryUuid;

    /** The execution of the firing that started {@code successorUuid}. */
    @Column(name = "execution_uuid")
    private UUID executionUuid;

    @Override
    public boolean equals(Object o) {
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
        CertificateRenewalLocation that = (CertificateRenewalLocation) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
