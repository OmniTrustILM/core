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
 * One in-flight async certificate operation awaiting a status poll: created on an authority
 * "in progress" (HTTP 202) response and deleted once the operation reaches a terminal state or times
 * out. Internal polling machinery, not a user-facing entity — hence no author/update audit columns.
 */
@Getter
@Setter
@Entity
// A certificate has at most one async operation in flight at a time.
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

    // Set by the database on insert, never written by the application — hence a read-only mapping.
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
