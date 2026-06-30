package com.otilm.core.dao.entity;

import com.otilm.core.service.handler.authority.CertificateOperation;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * One in-flight async certificate operation awaiting a status poll. A row is created when an
 * authority operation returns "in progress" (HTTP 202) and is deleted once the operation reaches a
 * terminal state (or times out). The {@code certificate_uuid} is unique — a certificate can have at
 * most one async operation in flight at a time.
 *
 * <p>{@code next_poll_at} is the due time the sweep scans for; {@code attempt} is how many polls have
 * been scheduled so far and indexes the backoff curve. This is internal polling machinery, not a
 * user-facing entity, so it carries no author/update audit columns — only a DB-populated creation timestamp.</p>
 */
@Getter
@Setter
@Entity
// The unique constraint on certificate_uuid backs the atomic scheduleIfAbsent insert
// (ON CONFLICT (certificate_uuid) DO NOTHING) — a certificate has at most one async operation in
// flight. Declared here (not only in the Flyway migration) so Hibernate-generated schema, used when
// Flyway is disabled, carries the constraint too.
@Table(name = "certificate_status_poll",
        uniqueConstraints = @UniqueConstraint(name = "uq_certificate_status_poll_certificate",
                columnNames = "certificate_uuid"))
public class CertificateStatusPoll extends UniquelyIdentified {

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "operation", nullable = false)
    private CertificateOperation operation;

    @Column(name = "attempt", nullable = false)
    private int attempt;

    @Column(name = "next_poll_at", nullable = false)
    private OffsetDateTime nextPollAt;

    // Populated by the DB default (the row is inserted via the native scheduleIfAbsent query, not a JPA
    // persist), so this is a read-only mapping — JPA never writes it. The columnDefinition carries the
    // DEFAULT now() into the Hibernate-generated schema (used when Flyway is disabled): the native insert
    // omits this column entirely, so without the default the NOT NULL would be violated.
    @Column(name = "i_cre", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz not null default now()")
    private OffsetDateTime created;

    // No-op override required by Sonar S2160 (a field-adding subclass of UniquelyIdentified must override
    // equals): identity stays the UUID and the added columns deliberately do not affect equality. Matches the
    // convention used by the other field-adding entities; dropping it just re-raises the finding.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
