package com.otilm.core.dao.entity;

import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cbom.CbomDto;
import com.otilm.core.util.DtoMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.Objects;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
// The unique constraint and the check below are stated here as well as in the migration so the entity-generated
// schema the tests run against carries the same invariants under the same names as production: the header sync tells
// a duplicate from any other refusal by reading `cbom_serial_version_unique` off the violation.
@Table(name = "cbom",
        uniqueConstraints = @UniqueConstraint(name = "cbom_serial_version_unique",
                columnNames = {"serial_number", "version"}))
@Check(name = "ck_cbom_asset_sync_state",
        constraints = "asset_sync_state IN ('PENDING', 'IN_PROGRESS', 'SYNCED', 'FAILED')")
public class Cbom extends UniquelyIdentified implements DtoMapper<CbomDto> {
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "serial_number", nullable = false)
    private String serialNumber;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "spec_version", nullable = false)
    private String specVersion;

    @Column(name = "timestamp", nullable = true, updatable = false)
    private OffsetDateTime timestamp;

    @Column(name = "source", nullable = true)
    private String source;

    @Column(name = "algorithms_count", nullable = false)
    private int algorithmsCount;

    @Column(name = "certificates_count", nullable = false)
    private int certificatesCount;

    @Column(name = "protocols_count", nullable = false)
    private int protocolsCount;

    @Column(name = "crypto_material_count", nullable = false)
    private int cryptoMaterialCount;

    @Column(name = "total_assets_count", nullable = false)
    private int totalAssetsCount;

    /**
     * Where this CBOM stands in cryptographic-asset ingest, independent of the header sync that created the row.
     * Existing header-only rows read as {@code PENDING}, which is correct: their assets have never been ingested.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "asset_sync_state", nullable = false, columnDefinition = "TEXT")
    private CbomAssetSyncState assetSyncState = CbomAssetSyncState.PENDING;

    /**
     * Why asset ingest last failed for this CBOM. Operator-visible, so the text is always shaped by us -- never a
     * driver message, whose DETAIL line carries the failing row.
     */
    @Column(name = "asset_sync_error", columnDefinition = "TEXT")
    private String assetSyncError;

    @Column(name = "assets_synced_at")
    private OffsetDateTime assetsSyncedAt;

    @Override
    public CbomDto mapToDto() {
        CbomDto dto = new CbomDto();

        dto.setUuid(this.uuid);
        dto.setCreatedAt(this.createdAt);
        dto.setSerialNumber(this.serialNumber);
        dto.setVersion(this.version);
        dto.setSpecVersion(this.specVersion);
        dto.setTimestamp(this.timestamp);
        dto.setSource(this.source);
        dto.setAlgorithms(this.algorithmsCount);
        dto.setCertificates(this.certificatesCount);
        dto.setProtocols(this.protocolsCount);
        dto.setCryptoMaterial(this.cryptoMaterialCount);
        dto.setTotalAssets(this.totalAssetsCount);
        dto.setAssetSyncState(this.assetSyncState);
        dto.setAssetSyncedAt(this.assetsSyncedAt);
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy hibernateProxy
                ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy hibernateProxy
                ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        Cbom that = (Cbom) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
