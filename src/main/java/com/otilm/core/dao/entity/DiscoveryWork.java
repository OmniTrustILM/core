package com.otilm.core.dao.entity;

import com.otilm.core.model.discovery.DiscoveryWorkType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Generated;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.hibernate.generator.EventType;

/**
 * One unit of pending discovery v2 work: created when a run starts owing a status poll, a drain or a processing pass,
 * rescheduled with backoff on failure, and deleted when the run stops owing it. Internal scheduling machinery, not a
 * user-facing entity — hence no author/update audit columns.
 */
@Getter
@Setter
@Entity
// A run owes at most one pending row per work type.
@Table(name = "discovery_work", uniqueConstraints = @UniqueConstraint(name = "uq_discovery_work",
        columnNames = {"discovery_uuid", "work_type"}))
public class DiscoveryWork extends UniquelyIdentified {

    @Column(name = "discovery_uuid", nullable = false)
    private UUID discoveryUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from
    // the entities; the writable column stays the scalar discoveryUuid above.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "discovery_uuid", insertable = false, updatable = false)
    private Discovery discovery;

    @Enumerated(EnumType.STRING)
    @Column(name = "work_type", nullable = false)
    private DiscoveryWorkType workType;

    @Column(name = "attempt", nullable = false)
    private int attempt;

    @Column(name = "next_due_at", nullable = false)
    private OffsetDateTime nextDueAt;

    // Set by the database on insert, never written by the application — hence a read-only mapping.
    // @Generated makes Hibernate re-read the DB-assigned value after a JPA insert, so the in-memory
    // entity never carries a null created while the row already has one.
    @Generated(event = EventType.INSERT)
    @Column(name = "i_cre", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz not null default now()")
    private OffsetDateTime created;

    // No-op overrides required by S2160: identity and hashing stay UUID-based, and the added columns never
    // affect equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
