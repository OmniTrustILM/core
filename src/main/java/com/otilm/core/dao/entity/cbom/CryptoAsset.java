package com.otilm.core.dao.entity.cbom;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
 * One deduplicated cryptographic asset, aggregated across every CBOM that reports it.
 *
 * <p>
 * The ten typed identity columns are the whole input to the identity key, and the key's uniqueness is what deduplicates
 * the inventory. {@code rulesetVersion} records which generation of the identity rules produced the key; it is
 * deliberately not part of the key's preimage, because folding it in would re-key every row on a rule-set bump.
 *
 * <p>
 * {@code mergedCryptoProperties} is not synthesised: it is byte-for-byte one source's retained payload, the richest
 * one, and {@code propertiesSourceUuid} names which. That is what makes the merge, and an alias built on top of it,
 * exactly reversible.
 */
@Getter
@Setter
@Entity
@Table(name = "crypto_asset",
        uniqueConstraints = @UniqueConstraint(name = "uq_crypto_asset_identity_key", columnNames = "identity_key"))
// Stated here as well as in the migration so the entity-generated schema the tests run against carries the same
// invariants and the same constraint names as production. A test that asserts a constraint by name would otherwise
// assert Hibernate's generated name and pass against a schema production does not have.
@Check(name = "ck_crypto_asset_properties_pair",
        constraints = "(merged_crypto_properties IS NULL) = (properties_hash IS NULL)")
@Check(name = "ck_crypto_asset_source_count", constraints = "source_count >= 0")
@Check(name = "ck_crypto_asset_properties_leaf_count", constraints = "properties_leaf_count >= 0")
@Check(name = "ck_crypto_asset_asset_type",
        constraints = "asset_type IN ('ALGORITHM', 'CERTIFICATE', 'PROTOCOL', 'RELATED_CRYPTO_MATERIAL', "
                + "'UNROUTABLE')")
@Check(name = "ck_crypto_asset_identity_guard",
        constraints = "identity_guard IN ('REFUTED_CERTIFICATE_DIGEST', 'BARE_CN_SUBJECT', 'REFUTED_OID')")
@Check(name = "ck_crypto_asset_pqc_verdict",
        constraints = "pqc_verdict IN ('READY', 'NOT_READY', 'NOT_APPLICABLE', 'UNKNOWN')")
@Check(name = "ck_crypto_asset_oid_length", constraints = "length(oid) <= 255")
@Check(name = "ck_crypto_asset_name_length", constraints = "length(name) <= 1024")
public class CryptoAsset extends UniquelyIdentifiedAndAudited {

    @Column(name = "identity_key", nullable = false, columnDefinition = "TEXT")
    private String identityKey;

    @Column(name = "ruleset_version", nullable = false)
    private int rulesetVersion;

    @Enumerated(EnumType.STRING)
    @Column(name = "asset_type", nullable = false, columnDefinition = "TEXT")
    private CryptographicAssetType assetType;

    @Column(name = "name", columnDefinition = "TEXT")
    private String name;

    @Column(name = "oid", columnDefinition = "TEXT")
    private String oid;

    @Column(name = "algorithm_family", columnDefinition = "TEXT")
    private String algorithmFamily;

    @Column(name = "primitive", columnDefinition = "TEXT")
    private String primitive;

    @Column(name = "parameter_set", columnDefinition = "TEXT")
    private String parameterSet;

    /**
     * The curve members, one per element. A hybrid scheme reports its members joined on {@code +} and is stored split,
     * so an asset can be found by any curve it touches; the identity preimage keeps the joined spelling.
     */
    @Column(name = "curve", columnDefinition = "TEXT[]")
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<String> curve;

    @Column(name = "mode", columnDefinition = "TEXT")
    private String mode;

    @Column(name = "padding", columnDefinition = "TEXT")
    private String padding;

    @Column(name = "variant", columnDefinition = "TEXT")
    private String variant;

    // The safety rule that forced this row to stay separate; null = none. CryptoAssetAliasWriter refuses to absorb a
    // guarded row or to point one at another, because the split was deliberate.
    @Enumerated(EnumType.STRING)
    @Column(name = "identity_guard", columnDefinition = "TEXT")
    private CryptoAssetIdentityGuard identityGuard;

    // S1948: every entity is Serializable via UniquelyIdentifiedObject, but nothing Java-serializes them -- Jackson
    // owns this JSONB field's persistence shape.
    @SuppressWarnings("java:S1948")
    @Column(name = "merged_crypto_properties", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> mergedCryptoProperties;

    @Column(name = "properties_leaf_count", nullable = false)
    private int propertiesLeafCount;

    @Column(name = "properties_hash", columnDefinition = "TEXT")
    private String propertiesHash;

    @Column(name = "properties_source_uuid")
    private UUID propertiesSourceUuid;

    // Mirrors ON DELETE SET NULL from the migration for the test environment, which generates its schema from the
    // entities; the writable column stays the scalar propertiesSourceUuid above. SET NULL rather than a dangling uuid,
    // so a merged payload whose source is gone is findable rather than plausible.
    @OnDelete(action = OnDeleteAction.SET_NULL)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "properties_source_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "crypto_asset_to_properties_source_key"))
    private CryptoAssetSource propertiesSource;

    @Column(name = "source_count", nullable = false)
    private int sourceCount;

    @Enumerated(EnumType.STRING)
    @Column(name = "pqc_verdict", columnDefinition = "TEXT")
    private PqcVerdict pqcVerdict;

    @Column(name = "pqc_rule_id", columnDefinition = "TEXT")
    private String pqcRuleId;

    @Column(name = "pqc_reason", columnDefinition = "TEXT")
    private String pqcReason;

    @Column(name = "pqc_ruleset_version")
    private Integer pqcRulesetVersion;

    /**
     * When the current verdict <em>value</em> was decided. Unmoved by a re-evaluation that reaches the same verdict.
     */
    @Column(name = "pqc_decided_at")
    private OffsetDateTime pqcDecidedAt;

    /** When the verdict was last evaluated, whether or not the value changed. */
    @Column(name = "pqc_evaluated_at")
    private OffsetDateTime pqcEvaluatedAt;

    // Which fields the rule actually read, so a verdict can be re-justified without re-running the rule set.
    @SuppressWarnings("java:S1948")
    @Column(name = "pqc_evaluated_fields", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> pqcEvaluatedFields;

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
