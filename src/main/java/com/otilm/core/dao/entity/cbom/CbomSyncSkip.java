package com.otilm.core.dao.entity.cbom;

import com.otilm.api.model.core.cbom.CbomSyncSkipDto;
import com.otilm.api.model.core.cbom.CbomSyncSkipState;
import com.otilm.core.dao.entity.UniquelyIdentified;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;

/**
 * A repository feed entry that a sync run could not store, remembered so it is not lost when the watermark moves past
 * it.
 *
 * <p>
 * The feed offers a document once: the next run lists from the start of the last successful run minus the overlap, so
 * an entry that failed -- its document unreadable for a moment, a Core validation refusing it -- would otherwise never
 * be offered again while the run still counted as successful. The row keeps the identity the repository serves
 * documents by, the counts the feed reported (so a recovered entry gets the same header a first-try entry gets), and
 * the attempt bookkeeping of the bounded retry. It is deleted the moment the document is stored, whichever state it is
 * in. A row whose budget is spent stays {@code PERMANENTLY_SKIPPED}: no run loads it again, but an operator sees it in
 * the sync-skip list of the CBOM inventory ({@code POST /v1/cboms/syncSkips}) and can ask for another attempt, which
 * puts it back to {@code RETRYING} with a full budget. A written-off row whose last attempt is older than the platform
 * setting {@code cbomSyncSkipRetentionDays} is removed by the daily {@code CbomSyncSkipRetentionTask}: age is the last
 * attempt, not the first failure, so a document the repository keeps offering stays listed while one it no longer lists
 * expires.
 *
 * <p>
 * {@code reason} is operator-visible, so it is always text Core shaped -- never a driver or framework message.
 */
@Getter
@Setter
@Entity
@Table(name = "cbom_sync_skip",
        uniqueConstraints = @UniqueConstraint(name = "uq_cbom_sync_skip_serial_version",
                columnNames = {"serial_number", "version"}))
@Check(name = "ck_cbom_sync_skip_state", constraints = "state IN ('RETRYING', 'PERMANENTLY_SKIPPED')")
public class CbomSyncSkip extends UniquelyIdentified {

    @Column(name = "serial_number", nullable = false, columnDefinition = "TEXT")
    private String serialNumber;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "reason", nullable = false, columnDefinition = "TEXT")
    private String reason;

    /** Sync runs that tried this entry, the one that first failed included. */
    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "first_skipped_at", nullable = false)
    private OffsetDateTime firstSkippedAt;

    @Column(name = "last_attempt_at", nullable = false)
    private OffsetDateTime lastAttemptAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, columnDefinition = "TEXT")
    private CbomSyncSkipState state;

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

    public CbomHeaderCounts counts() {
        return new CbomHeaderCounts(algorithmsCount, certificatesCount, protocolsCount, cryptoMaterialCount,
                totalAssetsCount);
    }

    /** The row as the operator list serves it: every member, the reason as stored. */
    public CbomSyncSkipDto mapToDto() {
        CbomSyncSkipDto dto = new CbomSyncSkipDto();
        dto.setUuid(getUuid());
        dto.setSerialNumber(serialNumber);
        dto.setVersion(version);
        dto.setState(state);
        dto.setAttempts(attempts);
        dto.setFirstSkippedAt(firstSkippedAt);
        dto.setLastAttemptAt(lastAttemptAt);
        dto.setReason(reason);
        dto.setAlgorithms(algorithmsCount);
        dto.setCertificates(certificatesCount);
        dto.setProtocols(protocolsCount);
        dto.setCryptoMaterial(cryptoMaterialCount);
        dto.setTotalAssets(totalAssetsCount);
        return dto;
    }

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
