package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.repository.cbom.CryptoAssetReferenceRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.ResolvedAssetReference;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Replaces the references one source recorded.
 *
 * <p>
 * The asset row is touched first, for two reasons. It is the lock order {@link CryptoAssetSourceWriter} documents --
 * asset row, then what hangs off it -- and it advances {@code input_revision}, so a verdict taken before the references
 * changed is stale to the sweep even if the ingest's own restamp never lands.
 */
@Service
public class CryptoAssetReferenceWriter {

    private final CryptoAssetReferenceRepository referenceRepository;
    private final CryptoAssetRepository assetRepository;

    public CryptoAssetReferenceWriter(CryptoAssetReferenceRepository referenceRepository,
            CryptoAssetRepository assetRepository) {
        this.referenceRepository = referenceRepository;
        this.assetRepository = assetRepository;
    }

    @Transactional
    /** @param seenAt the observation the source was upserted with; an older one leaves the references alone */
    public void replaceReferences(UUID assetUuid, UUID cbomUuid, OffsetDateTime seenAt,
            List<ResolvedAssetReference> references) {
        assetRepository.touch(assetUuid);
        referenceRepository.deleteForSource(assetUuid, cbomUuid, seenAt);
        for (ResolvedAssetReference reference : references) {
            referenceRepository
                    .insertForSource(UUID.randomUUID(), assetUuid, cbomUuid, seenAt, reference.kind().name(),
                            reference.ordinal(), reference.ref(), reference.suite(), reference.targetAssetUuid());
        }
    }
}
