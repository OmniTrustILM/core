package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.RenewalWindowSource;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.hibernate.proxy.HibernateProxy;

/**
 * The renewal state of a certificate. The certificate has a renewal window while {@code windowStart} is set. Window
 * columns are written only by {@code RenewalWindowWriter}; the refresh columns only by {@code RenewalRefreshWriter};
 * the automatic renewal columns by {@code AutoRenewalAction} and its handlers, under the row lock. A window change
 * clears the renewal time and the failure counters.
 */
@Entity
@Getter
@Setter
@ToString
@Table(name = "certificate_renewal_info",
        uniqueConstraints = @UniqueConstraint(name = "uq_certificate_renewal_info_certificate",
                columnNames = "certificate_uuid"))
public class CertificateRenewalInfo extends UniquelyIdentified implements Serializable {

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_uuid", insertable = false, updatable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ToString.Exclude
    private Certificate certificate;

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    @Column(name = "window_start")
    private Instant windowStart;

    @Column(name = "window_end")
    private Instant windowEnd;

    @Column(name = "explanation_url", columnDefinition = "TEXT")
    private String explanationUrl;

    @Column(name = "source", columnDefinition = "TEXT")
    @Enumerated(EnumType.STRING)
    private RenewalWindowSource source;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "advanced", nullable = false)
    private boolean advanced;

    @Column(name = "next_refresh_at")
    private Instant nextRefreshAt;

    @Column(name = "refresh_attempt", nullable = false, columnDefinition = "integer not null default 0")
    private int refreshAttempt;

    @Column(name = "refresh_unsupported", nullable = false, columnDefinition = "boolean not null default false")
    private boolean refreshUnsupported;

    @Column(name = "renew_at")
    private Instant renewAt;

    @Column(name = "renew_started_at")
    private Instant renewStartedAt;

    @Column(name = "renew_successor_uuid")
    private UUID renewSuccessorUuid;

    /** The trigger history of the firing that started {@code renewSuccessorUuid}, when a trigger started it. */
    @Column(name = "renew_trigger_history_uuid")
    private UUID renewTriggerHistoryUuid;

    /** The execution of that firing that started {@code renewSuccessorUuid}. */
    @Column(name = "renew_execution_uuid")
    private UUID renewExecutionUuid;

    /** The user the firing that started {@code renewSuccessorUuid} acted as. */
    @Column(name = "renew_owner_uuid")
    private UUID renewOwnerUuid;

    @Column(name = "renew_attempt", nullable = false, columnDefinition = "integer not null default 0")
    private int renewAttempt;

    @Column(name = "renew_not_before")
    private Instant renewNotBefore;

    @Column(name = "renew_blocked_reason", columnDefinition = "TEXT")
    private String renewBlockedReason;

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
        CertificateRenewalInfo that = (CertificateRenewalInfo) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
