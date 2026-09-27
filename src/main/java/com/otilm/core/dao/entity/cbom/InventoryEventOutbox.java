package com.otilm.core.dao.entity.cbom;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "inventory_event_outbox")
@Getter
@Setter
public class InventoryEventOutbox {

    @Id
    @Column(name = "cbom_uuid")
    private UUID cbomUuid;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "asset_uuids", nullable = false, columnDefinition = "uuid[]")
    private List<UUID> assetUuids;

    @Column(name = "cbom_synced", nullable = false)
    private boolean cbomSynced;

    @Column(name = "assets_ready", nullable = false)
    private boolean assetsReady;

    @Column(name = "cbom_user_uuid")
    private UUID cbomUserUuid;

    @Column(name = "claimed_until")
    private OffsetDateTime claimedUntil;

    @Column(name = "revision", nullable = false)
    private long revision;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
