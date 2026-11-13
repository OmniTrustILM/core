package com.otilm.core.dao.entity.est;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.UniquelyIdentified;
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
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

/**
 * The right to submit one EST request to the authority, held while identical concurrent requests wait for the resulting
 * certificate. Internal coordination state, not a user-facing entity — hence no audit columns.
 */
@Getter
@Setter
@Entity
@Table(name = "est_request_claim", uniqueConstraints = @UniqueConstraint(name = "uq_est_request_claim",
        columnNames = {"est_profile_uuid", "ra_profile_uuid", "operation", "request_key"}))
public class EstRequestClaim extends UniquelyIdentified {

    public enum Operation {
        ENROLL,
        REENROLL
    }

    @Column(name = "est_profile_uuid", nullable = false)
    private UUID estProfileUuid;

    @Column(name = "ra_profile_uuid", nullable = false)
    private UUID raProfileUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "operation", nullable = false)
    private Operation operation;

    @Column(name = "request_key", nullable = false, columnDefinition = "text")
    private String requestKey;

    @Column(name = "claimed_at", nullable = false)
    private OffsetDateTime claimedAt;

    /** The certificate that the claim's request stored, which every identical request answers from; null until then. */
    @Column(name = "certificate_uuid")
    private UUID certificateUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from
    // the entities; the writable column stays the scalar certificateUuid above.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_uuid", insertable = false, updatable = false)
    private Certificate certificate;

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
