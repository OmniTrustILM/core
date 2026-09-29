package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * One entry a certificate import request named. Kept, like {@code key_import} records, so a replay is answered from the
 * record instead of running the entry again.
 */
@Getter
@Setter
@Entity
@Table(name = "certificate_import_entry", uniqueConstraints = @UniqueConstraint(name = "uq_certificate_import_entry",
        columnNames = {"requester_uuid", "import_id"}))
public class CertificateImportEntry extends UniquelyIdentified {

    @Column(name = "requester_uuid", nullable = false, updatable = false)
    private UUID requesterUuid;

    @Column(name = "import_id", nullable = false, updatable = false, length = 256)
    private String importId;

    /** SHA-256 of what the entry asks for; the passphrase is not part of it. */
    @Column(name = "digest", nullable = false, updatable = false, length = 64)
    private String digest;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, length = 16)
    private CertificateImportEntryState state;

    @Column(name = "certificate_uuid")
    private UUID certificateUuid;

    @Column(name = "key_uuid")
    private UUID keyUuid;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    // No-op override required by Sonar S2160 (a field-adding subclass of UniquelyIdentified must override
    // equals): identity stays the UUID and the added columns deliberately do not affect equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
