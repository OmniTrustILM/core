package com.otilm.core.dao.entity.cbom;

import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

/**
 * The repair path for an accidental duplicate: a decision that one asset key is really another.
 *
 * <p>
 * Nothing in the keying path reads this table. The identity calculator sees the ten typed columns and nothing else, so
 * an alias cannot affect whether a key conforms. The alias is consumed one layer up, at upsert time, which is how it
 * survives re-ingest: a re-ingest of the absorbed CBOM resolves through the alias onto the canonical row instead of
 * recreating the duplicate.
 *
 * <p>
 * {@code absorbedKey} deliberately carries no foreign key -- by the time the alias exists, that asset row is gone, so a
 * reference would be unsatisfiable. {@code canonicalKey} does: an alias pointing at an asset that no longer exists is a
 * lie.
 */
@Getter
@Setter
@Entity
@Table(name = "crypto_asset_alias",
        uniqueConstraints = @UniqueConstraint(name = "uq_crypto_asset_alias_absorbed", columnNames = "absorbed_key"))
// Stated here as well as in the migration, so the entity-generated schema the tests run against carries the same
// invariant and the same constraint name as production.
@Check(name = "ck_crypto_asset_alias_not_self", constraints = "absorbed_key <> canonical_key")
public class CryptoAssetAlias extends UniquelyIdentified {

    @Column(name = "absorbed_key", nullable = false, columnDefinition = "TEXT")
    private String absorbedKey;

    @Column(name = "canonical_key", nullable = false, columnDefinition = "TEXT")
    private String canonicalKey;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from the
    // entities; the writable column stays the scalar canonicalKey above. The reference is to the asset's unique
    // identity key, not to its surrogate uuid, because that is the vocabulary the operator decides in.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "canonical_key", referencedColumnName = "identity_key", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "crypto_asset_alias_to_canonical_key"))
    private CryptoAsset canonicalAsset;

    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    @Column(name = "decided_by", columnDefinition = "TEXT")
    private String decidedBy;

    @Column(name = "decided_at", nullable = false)
    private OffsetDateTime decidedAt;

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
