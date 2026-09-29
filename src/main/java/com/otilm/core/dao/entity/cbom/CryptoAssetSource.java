package com.otilm.core.dao.entity.cbom;

import com.otilm.core.dao.entity.Cbom;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.hibernate.type.SqlTypes;

/**
 * One CBOM's contribution to one cryptographic asset: the payload that CBOM reported, the evidence of where it was
 * seen, and how often.
 *
 * <p>
 * {@code originalCryptoProperties} is retained per source rather than merged away. That retention is what makes the
 * asset-level merge reversible and an alias repair exact: undoing either re-derives everything from the payloads that
 * are still here, with nothing to reconstruct.
 *
 * <p>
 * {@code occurrenceCount} counts what was seen, including occurrences the evidence cap dropped, so the gap against the
 * retained {@code evidence} array is the visible record that capping happened.
 */
@Getter
@Setter
@Entity
@Table(name = "crypto_asset_source",
        uniqueConstraints = @UniqueConstraint(name = "uq_crypto_asset_source",
                columnNames = {"asset_uuid", "cbom_uuid"}))
// Stated here as well as in the migration, so the entity-generated schema the tests run against carries the same
// invariants and the same constraint names as production.
@Check(name = "ck_crypto_asset_source_occurrence_count", constraints = "occurrence_count >= 0")
@Check(name = "ck_crypto_asset_source_properties_leaf_count", constraints = "properties_leaf_count >= 0")
public class CryptoAssetSource extends UniquelyIdentified {

    @Column(name = "asset_uuid", nullable = false)
    private UUID assetUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from the
    // entities; the writable column stays the scalar assetUuid above. A source reference has no meaning without its
    // asset.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "asset_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "crypto_asset_source_to_crypto_asset_key"))
    private CryptoAsset asset;

    @Column(name = "cbom_uuid", nullable = false)
    private UUID cbomUuid;

    // Mirrors ON DELETE RESTRICT from the migration. Dropping a CBOM row must not silently erase inventory
    // provenance: deletion goes through the service path, which detaches the sources first.
    @OnDelete(action = OnDeleteAction.RESTRICT)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cbom_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "crypto_asset_source_to_cbom_key"))
    private Cbom cbom;

    // S1948: every entity is Serializable via UniquelyIdentifiedObject, but nothing Java-serializes them -- Jackson
    // owns this JSONB field's persistence shape.
    @SuppressWarnings("java:S1948")
    @Column(name = "original_crypto_properties", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> originalCryptoProperties;

    @Column(name = "properties_leaf_count", nullable = false)
    private int propertiesLeafCount;

    @Column(name = "properties_hash", columnDefinition = "TEXT")
    private String propertiesHash;

    // Capped, never truncated: see OccurrenceEvidenceCapper for why additionalContext is dropped whole.
    @SuppressWarnings("java:S1948")
    @Column(name = "evidence", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<Map<String, Object>> evidence;

    @Column(name = "occurrence_count", nullable = false)
    private int occurrenceCount;

    /**
     * The {@code bom-ref} values of the components this CBOM folded into the asset, in document order and capped
     * ({@code CbomAssetExtractor.ExtractedAsset#storedBomRefs}). Navigation data only -- never an input to how the
     * asset is keyed, to the canonical projection or to {@code propertiesHash}. Empty when no component could be
     * linked: a ref no text column can hold links nothing, and a document that defines a ref more than once is refused
     * whole. Assigned whole under the same recency rule as the payload, never accumulated.
     */
    @Column(name = "bom_refs", columnDefinition = "TEXT[]", nullable = false)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<String> bomRefs = List.of();

    @Column(name = "first_seen_at", nullable = false)
    private OffsetDateTime firstSeenAt;

    @Column(name = "last_seen_at", nullable = false)
    private OffsetDateTime lastSeenAt;

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
