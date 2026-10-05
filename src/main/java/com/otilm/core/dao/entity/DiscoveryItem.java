package com.otilm.core.dao.entity;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.auth.Resource;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.hibernate.type.SqlTypes;

/**
 * One staged discovery item, whatever its resource type: the run-scoped record of something a Discovery Provider
 * reported, held until processing turns it into an inventory object — or records, on the row itself, why it could not.
 *
 * <p>
 * {@code payload} keeps the connector-reported union untyped ({@code Map}): staging must never fail on a payload shape
 * this Core version does not know yet, and the typed view is synthesized at read time where a failure can be answered,
 * not dropped.
 */
@Getter
@Setter
@Entity
@Table(name = "discovery_item", uniqueConstraints = @UniqueConstraint(name = "uq_discovery_item_ref",
        columnNames = {"discovery_uuid", "resource", "unique_ref"}))
public class DiscoveryItem extends UniquelyIdentified {

    @Column(name = "discovery_uuid", nullable = false)
    private UUID discoveryUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from
    // the entities; the writable column stays the scalar discoveryUuid above.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "discovery_uuid", insertable = false, updatable = false)
    private Discovery discovery;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource", nullable = false)
    private Resource resource;

    // The run-wide dense cursor assigned by the connector, starting at 1 — never page-scoped.
    @Column(name = "sequence", nullable = false)
    private long sequence;

    @Column(name = "unique_ref", nullable = false)
    private String uniqueRef;

    // S1948: every entity is Serializable via UniquelyIdentifiedObject, but nothing Java-serializes them —
    // Jackson owns this JSONB field's persistence shape.
    @SuppressWarnings("java:S1948")
    @Column(name = "payload", columnDefinition = "jsonb", nullable = false)
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> payload;

    @Column(name = "discovered_at")
    private OffsetDateTime discoveredAt;

    @Column(name = "processed_at")
    private OffsetDateTime processedAt;

    @Column(name = "processed_error")
    private String processedError;

    // Object this item became; null until processed, permanently null if processing failed.
    @Column(name = "inventory_uuid")
    private UUID inventoryUuid;

    // Not already in inventory when staged, matched by fingerprint.
    @Column(name = "newly_discovered", nullable = false)
    private boolean newlyDiscovered;

    // Provider-reported location context; unrecoverable if dropped at staging — key location lives here.
    @Column(name = "meta", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<MetadataAttribute> meta;

    // Metadata attributes the connector declared encrypted, kept out of meta and encrypted; see StagedMetadata.
    @Column(name = "protected_meta", length = Integer.MAX_VALUE)
    private String protectedMeta;

    // No-op overrides required by S2160: identity and hashing stay UUID-based, and the added columns never
    // affect equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
