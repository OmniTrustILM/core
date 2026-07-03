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
 * replayed by the register-bound issue, and cleared once issuance completes. {@code meta} carries the
 * connector-returned CA tracking handle.
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

    // Set by the database on insert, never by the application.
    @Column(name = "i_cre", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz not null default now()")
    private OffsetDateTime created;

    // Maintained by the upsert SQL (audit-columns-in-SQL rule); read-only on the entity.
    @Column(name = "i_upd", nullable = false, insertable = false, updatable = false,
            columnDefinition = "timestamptz not null default now()")
    private OffsetDateTime updated;

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
