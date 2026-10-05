package com.otilm.core.cbom.ingest;

import com.otilm.api.model.common.events.data.CryptoAssetAddedEventData;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.core.cbom.sync.CbomSyncPolicyProvider;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.InventoryEventOutbox;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.InventoryEventOutboxRepository;
import com.otilm.core.events.handlers.CbomSyncedEventHandler;
import com.otilm.core.events.handlers.CryptoAssetAddedEventHandler;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.service.writer.cbom.InventoryEventOutboxWriter;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/** Sends committed inventory events and retries rows left behind by a crash or broker outage. */
@Slf4j
@Component
public class InventoryEventOutboxDispatcher {

    private static final int BATCH_SIZE = 100;

    private final InventoryEventOutboxRepository repository;
    private final InventoryEventOutboxWriter writer;
    private final CbomRepository cbomRepository;
    private final CryptoAssetRepository assetRepository;
    private final CbomAssetDetachService detachService;
    private final CbomSyncPolicyProvider policyProvider;
    private final EventProducer producer;

    public InventoryEventOutboxDispatcher(InventoryEventOutboxRepository repository, InventoryEventOutboxWriter writer,
            CbomRepository cbomRepository, CryptoAssetRepository assetRepository, CbomAssetDetachService detachService,
            CbomSyncPolicyProvider policyProvider, EventProducer producer) {
        this.repository = repository;
        this.writer = writer;
        this.cbomRepository = cbomRepository;
        this.assetRepository = assetRepository;
        this.detachService = detachService;
        this.policyProvider = policyProvider;
        this.producer = producer;
    }

    public void dispatchReady() {
        List<UUID> ready = repository.findReadyBatch(BATCH_SIZE);
        for (UUID cbomUuid : ready) {
            dispatchCbom(cbomUuid);
        }
    }

    public void dispatchCbom(UUID cbomUuid) {
        OffsetDateTime leaseUntil = OffsetDateTime.now().plusMinutes(5).truncatedTo(ChronoUnit.MICROS);
        try {
            if (writer.claim(cbomUuid, leaseUntil) == 0) {
                return;
            }
            InventoryEventOutbox row = repository.findById(cbomUuid).orElse(null);
            if (row == null) {
                return;
            }
            Cbom cbom = cbomRepository.findById(cbomUuid).orElse(null);
            boolean assetsReady = cbom != null
                    && ((row.isAssetsReady() && cbom.getAssetSyncState() != CbomAssetSyncState.IN_PROGRESS)
                            || cbom.getAssetSyncState() == CbomAssetSyncState.FAILED);
            if ((!row.isCbomSynced() && !assetsReady) || cbom == null) {
                if (cbom != null) {
                    writer.release(cbomUuid, leaseUntil);
                } else {
                    if (writer.deleteIfUnchanged(cbomUuid, row.getRevision(), leaseUntil) == 0) {
                        writer.release(cbomUuid, leaseUntil);
                    }
                }
                return;
            }
            if (row.isCbomSynced()) {
                List<UUID> superseded = cbomRepository.findSupersededVersionUuids(cbomUuid);
                if (!superseded.isEmpty()) {
                    int batchSize = policyProvider.current().assetBatchSize();
                    for (UUID olderVersion : superseded) {
                        detachService.withdrawWaiting(olderVersion, batchSize);
                    }
                }
            } else if (cbomRepository.hasIngestedLaterVersion(cbomUuid)) {
                detachService.withdrawWaiting(cbomUuid, policyProvider.current().assetBatchSize());
            }
            Optional<List<CryptoAssetAddedEventData>> survivingAssets = survivingAssets(cbomUuid, row.getAssetUuids());
            if (survivingAssets.isEmpty()) {
                writer.release(cbomUuid, leaseUntil);
                return;
            }
            if (row.isCbomSynced()) {
                producer
                        .produceMessage(CbomSyncedEventHandler
                                .constructEventMessage(cbomUuid, CbomSyncedEventHandler.snapshot(cbom),
                                        survivingAssets.get(), row.getCbomUserUuid()));
            } else if (!survivingAssets.get().isEmpty()) {
                producer
                        .produceMessage(CryptoAssetAddedEventHandler
                                .constructEventMessage(cbomUuid, survivingAssets.get(), row.getCbomUserUuid()));
            }
            if (writer.deleteIfUnchanged(cbomUuid, row.getRevision(), leaseUntil) == 0) {
                if (!row.isCbomSynced() && writer
                        .acknowledgeSentPrefix(cbomUuid, row.getRevision(), leaseUntil,
                                row.getAssetUuids().size()) == 1) {
                    writer.deleteEmpty(cbomUuid, leaseUntil);
                }
                writer.release(cbomUuid, leaseUntil);
            }
        } catch (Exception e) {
            log.warn("Could not dispatch inventory events for CBOM {}; the outbox will retry", cbomUuid, e);
            try {
                writer.release(cbomUuid, leaseUntil);
            } catch (RuntimeException releaseError) {
                log.warn("Could not release the inventory event claim for CBOM {}", cbomUuid, releaseError);
            }
        }
    }

    private Optional<List<CryptoAssetAddedEventData>> survivingAssets(UUID cbomUuid, List<UUID> assetUuids) {
        if (assetUuids.isEmpty()) {
            return Optional.of(List.of());
        }
        Map<UUID, CryptoAsset> assets = assetRepository
                .findSourcedAssets(assetUuids)
                .stream()
                .collect(Collectors.toMap(CryptoAsset::getUuid, Function.identity()));
        if (assets.values().stream().anyMatch(asset -> !hasCurrentVerdict(asset))) {
            return Optional.empty();
        }
        if (!assets.isEmpty() && !assetRepository.findStaleVerdictUuids(assetUuids).isEmpty()) {
            return Optional.empty();
        }
        return Optional
                .of(assetUuids
                        .stream()
                        .map(assets::get)
                        .filter(asset -> asset != null)
                        .map(asset -> CryptoAssetAddedEventHandler.snapshot(asset, cbomUuid))
                        .toList());
    }

    private static boolean hasCurrentVerdict(CryptoAsset asset) {
        return asset.getPqcVerdict() != null && asset.getPqcEvaluatedRevision() != null
                && asset.getPqcEvaluatedRevision() == asset.getInputRevision();
    }
}
