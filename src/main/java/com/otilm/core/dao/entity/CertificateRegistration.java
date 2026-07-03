package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Register->issue binding for a pre-registered certificate: created when the authority accepts a registration,
 * replayed under a pessimistic lock by the register-bound issue, and cleared once issuance completes. {@code meta}
 * carries the connector-returned CA tracking handle (null when none). Internal machinery — no author column.
 */
@Getter
@Setter
@Entity
// A certificate has at most one registration binding at a time.
@Table(name = "certificate_registration",
        uniqueConstraints = @UniqueConstraint(name = "uq_certificate_registration_certificate",
                columnNames = "certificate_uuid"))
public class CertificateRegistration extends UniquelyIdentified {

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    /** Serialized {@code List<MetadataAttribute>} — the CA handle returned by the register operation. */
    @Column(name = "meta", length = Integer.MAX_VALUE)
    private String meta;

    // Read-only mapping: set by the database on insert, never by the application.
    @Column(name = "i_cre", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz not null default now()")
    private OffsetDateTime created;

    // Maintained by the upsert SQL (audit-columns-in-SQL rule); read-only on the entity.
    @Column(name = "i_upd", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz not null default now()")
    private OffsetDateTime updated;

    // Sonar S2160: a field-adding subclass of UniquelyIdentified must override equals. Identity stays the UUID;
    // the added columns deliberately do not affect equality, matching the other field-adding entities.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
