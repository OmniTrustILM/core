package com.otilm.core.dao.entity.cbom;

import com.otilm.core.dao.entity.UniquelyIdentified;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

/**
 * One reference a source's component made to another component of the same document, resolved to the inventory asset
 * that component became. Written by the ingest, which is the only place the document's bom-refs are in hand.
 *
 * <p>
 * Per source rather than per asset: an asset several documents report may reference different components in each, and
 * only the source whose payload the merge elected speaks for the row. A null target is a reference recorded and
 * resolved to nothing, which a verdict reports differently from no reference at all.
 */
@Getter
@Setter
@Entity
@Table(name = "crypto_asset_reference",
        uniqueConstraints = @UniqueConstraint(name = "uq_crypto_asset_reference",
                columnNames = {"source_uuid", "kind", "ordinal"}),
        indexes = @Index(name = "idx_crypto_asset_reference_target", columnList = "target_asset_uuid"))
// Stated here as well as in the migration, so the entity-generated schema the tests run against carries the same
// invariants and the same constraint names as production.
@Check(name = "ck_crypto_asset_reference_kind",
        constraints = "kind IN ('SUBJECT_PUBLIC_KEY', 'SIGNATURE_ALGORITHM', 'CIPHER_SUITE_ALGORITHM')")
@Check(name = "ck_crypto_asset_reference_ordinal", constraints = "ordinal >= 0")
public class CryptoAssetReference extends UniquelyIdentified {

    @Column(name = "source_uuid", nullable = false)
    private UUID sourceUuid;

    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "crypto_asset_reference_to_source_key"))
    private CryptoAssetSource source;

    @Enumerated(EnumType.STRING)
    @Column(name = "kind", nullable = false, columnDefinition = "TEXT")
    private CryptoAssetReferenceKind kind;

    @Column(name = "ordinal", nullable = false)
    private int ordinal;

    @Column(name = "ref", nullable = false, columnDefinition = "TEXT")
    private String ref;

    @Column(name = "suite", columnDefinition = "TEXT")
    private String suite;

    @Column(name = "target_asset_uuid")
    private UUID targetAssetUuid;

    // A deleted target leaves the reference dangling rather than taking it along: it was recorded, and a verdict says
    // so.
    @OnDelete(action = OnDeleteAction.SET_NULL)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "target_asset_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "crypto_asset_reference_to_target_key"))
    private CryptoAsset target;
}
