package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.repository.cbom.InventoryEventOutboxRepository;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InventoryEventOutboxWriter {

    private final InventoryEventOutboxRepository repository;

    public InventoryEventOutboxWriter(InventoryEventOutboxRepository repository) {
        this.repository = repository;
    }

    /** Joins the asset batch transaction, so an inserted asset never commits without its event intent. */
    @Transactional
    public void recordAddedAssets(UUID cbomUuid, List<UUID> assetUuids) {
        if (!assetUuids.isEmpty()) {
            repository.recordAddedAssets(cbomUuid, assetUuids.toArray(UUID[]::new));
        }
    }

    /** Joins the state transition transaction. */
    @Transactional
    public void recordCbomSynced(UUID cbomUuid, UUID userUuid) {
        repository.recordCbomSynced(cbomUuid, userUuid);
    }

    @Transactional
    public void markAssetsReady(UUID cbomUuid) {
        repository.markAssetsReady(cbomUuid);
    }

    @Transactional
    public int claim(UUID cbomUuid, OffsetDateTime leaseUntil) {
        return repository.claim(cbomUuid, leaseUntil);
    }

    @Transactional
    public int deleteIfUnchanged(UUID cbomUuid, long revision, OffsetDateTime leaseUntil) {
        return repository.deleteIfUnchanged(cbomUuid, revision, leaseUntil);
    }

    @Transactional
    public int acknowledgeSentPrefix(UUID cbomUuid, long revision, OffsetDateTime leaseUntil, int sentCount) {
        return repository.acknowledgeSentPrefix(cbomUuid, revision, leaseUntil, sentCount);
    }

    @Transactional
    public void deleteEmpty(UUID cbomUuid, OffsetDateTime leaseUntil) {
        repository.deleteEmpty(cbomUuid, leaseUntil);
    }

    @Transactional
    public void release(UUID cbomUuid, OffsetDateTime leaseUntil) {
        repository.release(cbomUuid, leaseUntil);
    }
}
