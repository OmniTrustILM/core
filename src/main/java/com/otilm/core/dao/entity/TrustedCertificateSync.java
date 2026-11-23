package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;

/**
 * Health of the comparison between the trusted certificates and the platform: one row, inserted by the migration.
 */
@Getter
@Setter
@Entity
@Table(name = "trusted_certificate_sync")
public class TrustedCertificateSync extends UniquelyIdentified {

    public static final UUID SINGLETON_UUID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Column(name = "initial_import_done", nullable = false)
    private boolean initialImportDone;

    @Column(name = "last_successful_check_at")
    private OffsetDateTime lastSuccessfulCheckAt;

    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;

    // No-op overrides required by S2160: identity and hashing stay UUID-based, and the added columns never affect
    // equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
