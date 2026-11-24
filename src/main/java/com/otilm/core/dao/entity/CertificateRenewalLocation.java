package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

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
}
