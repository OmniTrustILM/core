package com.otilm.core.dao.entity;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.hibernate.proxy.HibernateProxy;

/**
 * One kind of problem a discovery run reported, with how often it happened. A repeat of the same {@code code} and text
 * advances {@code occurrences} and {@code lastSeenAt} rather than adding a row, so a run against a broken estate cannot
 * bury its own first and most useful entry.
 *
 * <p>
 * Read-only through JPA: every write goes through {@code DiscoveryMessageWriter}'s upsert.
 */
@Getter
@Setter
@ToString
@Entity
@Table(name = "discovery_message",
        uniqueConstraints = @UniqueConstraint(name = "uq_discovery_message",
                columnNames = {"discovery_uuid", "code", "message_hash"}),
        indexes = @Index(name = "idx_discovery_message_run", columnList = "discovery_uuid, id"))
public class DiscoveryMessage {

    /**
     * The run's ordering key, never exposed. A timestamp cannot serve: {@code now()} is transaction-start time, so
     * every message one tick writes would tie, and a wall-clock column inverts across pods under clock skew.
     */
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "discovery_uuid", nullable = false)
    private UUID discoveryUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from
    // the entities; the writable column stays the scalar discoveryUuid above.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "discovery_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Discovery discovery;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private DiscoveryMessageSeverity severity;

    @Column(name = "code", nullable = false)
    private String code;

    @Column(name = "message", nullable = false)
    private String message;

    /**
     * Computed by the database, and mapped only so the test schema — generated from these annotations — carries the
     * column the upsert's conflict target names. Hashed to keep that index entry inside the btree limit.
     */
    @Column(name = "message_hash", columnDefinition = "varchar generated always as (md5(message)) stored",
            insertable = false, updatable = false)
    private String messageHash;

    @Column(name = "occurrences", nullable = false)
    private long occurrences;

    // Both stamped by the database rather than by whichever pod appended, so the window a fault was active in
    // reads the same however many nodes contributed to it. Transaction-start time, so they are a window and not
    // an order -- see id.
    @Column(name = "first_seen_at", nullable = false)
    private OffsetDateTime firstSeenAt;

    @Column(name = "last_seen_at", nullable = false)
    private OffsetDateTime lastSeenAt;

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
        DiscoveryMessage that = (DiscoveryMessage) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
