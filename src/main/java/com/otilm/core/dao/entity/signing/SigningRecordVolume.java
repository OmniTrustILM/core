package com.otilm.core.dao.entity.signing;

import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;

/**
 * How many signings a signing profile performed in one UTC hour, kept after the {@link SigningRecord} rows themselves
 * are gone. A record proves what a signing contained; this row preserves that the signing happened, which has to
 * survive the record being deleted by an operator, by retention, or by delete-after-retrieval.
 *
 * <p>
 * Rows are written only by the roll-up-then-delete statements on
 * {@link com.otilm.core.dao.repository.signing.SigningRecordRepository}: a bucket is created or incremented in the same
 * statement that removes the records it accounts for, so a count can neither double-count nor drift. Nothing amends a
 * bucket afterwards and nothing deletes one, which is what makes the history immutable.
 */
@Getter
@Setter
@Entity
@Table(name = "signing_record_volume", uniqueConstraints = @UniqueConstraint(name = "uq_signing_record_volume_bucket",
        columnNames = {"signing_profile_uuid", "bucket_start"}))
public class SigningRecordVolume extends UniquelyIdentified {

    /**
     * The signing profile the signings were performed under. Deliberately not a mapped association: a profile becomes
     * deletable once its records are gone and these counts outlive it, so the reference would be unsatisfiable. The
     * column stays the access-control anchor — signing history is scoped by signing-profile access.
     */
    @Column(name = "signing_profile_uuid", nullable = false)
    private UUID signingProfileUuid;

    @Column(name = "bucket_start", nullable = false)
    private Instant bucketStart;

    @Column(name = "signing_count", nullable = false)
    private long signingCount;

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
