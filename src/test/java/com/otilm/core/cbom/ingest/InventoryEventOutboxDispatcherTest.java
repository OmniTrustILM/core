package com.otilm.core.cbom.ingest;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.cbom.sync.CbomSyncPolicyProvider;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.InventoryEventOutbox;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.InventoryEventOutboxRepository;
import com.otilm.core.events.handlers.CbomSyncedEventPayload;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.service.writer.cbom.InventoryEventOutboxWriter;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InventoryEventOutboxDispatcherTest {

    private final InventoryEventOutboxRepository repository = mock(InventoryEventOutboxRepository.class);
    private final InventoryEventOutboxWriter writer = mock(InventoryEventOutboxWriter.class);
    private final CbomRepository cboms = mock(CbomRepository.class);
    private final CryptoAssetRepository assets = mock(CryptoAssetRepository.class);
    private final CbomAssetDetachService detachService = mock(CbomAssetDetachService.class);
    private final CbomSyncPolicyProvider policyProvider = mock(CbomSyncPolicyProvider.class);
    private final EventProducer producer = mock(EventProducer.class);
    private final InventoryEventOutboxDispatcher dispatcher = new InventoryEventOutboxDispatcher(repository, writer,
            cboms, assets, detachService, policyProvider, producer);
    private final UUID cbomUuid = UUID.randomUUID();

    @Test
    void completedCbomSendsOneBulkMessageBeforeRemovingItsIntent() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        givenRow(true, List.of(first, second));
        givenCbom();
        when(assets.findSourcedAssets(List.of(first, second))).thenReturn(List.of(asset(first), asset(second)));

        dispatcher.dispatchCbom(cbomUuid);

        ArgumentCaptor<EventMessage> event = ArgumentCaptor.forClass(EventMessage.class);
        InOrder order = inOrder(producer, writer);
        order.verify(producer).produceMessage(event.capture());
        order.verify(writer).deleteIfUnchanged(eq(cbomUuid), eq(0L), any());
        assertThat(event.getValue().getEvent()).isEqualTo(ResourceEvent.CBOM_SYNCED);
        CbomSyncedEventPayload payload = (CbomSyncedEventPayload) event.getValue().getData();
        assertThat(payload.assets()).extracting("cryptoAssetUuid").containsExactly(first, second);
        assertThat(payload.cbom().getSource()).isEqualTo("scanner");
        assertThat(payload.cbom().getTotalAssets()).isEqualTo(2);
    }

    @Test
    void brokerFailureLeavesTheIntentForRetry() {
        givenRow(true, List.of(UUID.randomUUID()));
        givenCbom();
        doThrow(new IllegalStateException("broker unavailable")).when(producer).produceMessage(any());

        dispatcher.dispatchCbom(cbomUuid);

        verify(writer).release(eq(cbomUuid), any());
        verify(writer, never()).deleteIfUnchanged(any(), anyLong(), any());
    }

    @Test
    void anUnsettledCbomKeepsNewAssetsUntilItsOutcomeIsKnown() {
        givenRow(false, List.of(UUID.randomUUID()));
        givenCbom();

        dispatcher.dispatchCbom(cbomUuid);

        verify(producer, never()).produceMessage(any());
        verify(writer).release(eq(cbomUuid), any());
    }

    @Test
    void aCompletedCbomWaitsForItsNewAssetsVerdictsBeforePublishingTriggers() {
        UUID newAsset = UUID.randomUUID();
        givenRow(true, List.of(newAsset));
        givenCbom();
        CryptoAsset asset = asset(newAsset);
        asset.setPqcVerdict(null);
        when(assets.findSourcedAssets(List.of(newAsset))).thenReturn(List.of(asset));

        dispatcher.dispatchCbom(cbomUuid);

        verify(producer, never()).produceMessage(any());
        verify(writer).release(eq(cbomUuid), any());
        verify(writer, never()).deleteIfUnchanged(any(), anyLong(), any());
    }

    @Test
    void aVerdictForAnOldInputRevisionKeepsTheEventPending() {
        UUID newAsset = UUID.randomUUID();
        givenRow(true, List.of(newAsset));
        givenCbom();
        CryptoAsset asset = asset(newAsset);
        asset.setPqcEvaluatedRevision(0L);
        when(assets.findSourcedAssets(List.of(newAsset))).thenReturn(List.of(asset));

        dispatcher.dispatchCbom(cbomUuid);

        verify(producer, never()).produceMessage(any());
        verify(writer).release(eq(cbomUuid), any());
    }

    @Test
    void aVerdictForAPreviousAssetMergeKeepsTheEventPending() {
        UUID newAsset = UUID.randomUUID();
        givenRow(true, List.of(newAsset));
        givenCbom();
        CryptoAsset asset = asset(newAsset);
        asset.setInputRevision(2L);
        when(assets.findSourcedAssets(List.of(newAsset))).thenReturn(List.of(asset));

        dispatcher.dispatchCbom(cbomUuid);

        verify(producer, never()).produceMessage(any());
        verify(writer).release(eq(cbomUuid), any());
    }

    @Test
    void aFailedCbomPublishesOnlyNewAssetsThatRemainInInventory() {
        UUID surviving = UUID.randomUUID();
        UUID removed = UUID.randomUUID();
        givenRow(false, List.of(surviving, removed));
        givenCbom();
        when(assets.findSourcedAssets(List.of(surviving, removed))).thenReturn(List.of(asset(surviving)));
        when(cboms.hasIngestedLaterVersion(cbomUuid)).thenReturn(true);
        when(policyProvider.current()).thenReturn(CbomSyncPolicy.DEFAULTS);
        when(repository.findById(cbomUuid)).thenAnswer(call -> {
            InventoryEventOutbox row = new InventoryEventOutbox();
            row.setCbomUuid(cbomUuid);
            row.setAssetUuids(List.of(surviving, removed));
            row.setAssetsReady(true);
            return Optional.of(row);
        });

        dispatcher.dispatchCbom(cbomUuid);

        ArgumentCaptor<EventMessage> event = ArgumentCaptor.forClass(EventMessage.class);
        verify(producer).produceMessage(event.capture());
        assertThat(event.getValue().getEvent()).isEqualTo(ResourceEvent.CRYPTO_ASSET_ADDED);
        assertThat((List<?>) event.getValue().getData()).extracting("cryptoAssetUuid").containsExactly(surviving);
        InOrder order = inOrder(detachService, producer);
        order.verify(detachService).withdrawWaiting(cbomUuid, CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE);
        order.verify(producer).produceMessage(any());
    }

    @Test
    void aDeletedCbomDiscardsItsIncompleteIntent() {
        givenRow(false, List.of(UUID.randomUUID()));

        dispatcher.dispatchCbom(cbomUuid);

        verify(producer, never()).produceMessage(any());
        verify(writer).deleteIfUnchanged(eq(cbomUuid), eq(0L), any());
    }

    @Test
    void aLaterVersionDoesNotCancelAnAlreadyCommittedSyncEvent() {
        givenRow(true, List.of());
        givenCbom();

        dispatcher.dispatchCbom(cbomUuid);

        ArgumentCaptor<EventMessage> event = ArgumentCaptor.forClass(EventMessage.class);
        verify(producer).produceMessage(event.capture());
        assertThat(event.getValue().getEvent()).isEqualTo(ResourceEvent.CBOM_SYNCED);
        verify(cboms, never()).hasIngestedLaterVersion(cbomUuid);
    }

    @Test
    void reattachedOldSourcesAreWithdrawnBeforeTheNewerCbomEvent() {
        UUID older = UUID.randomUUID();
        givenRow(true, List.of());
        givenCbom();
        when(cboms.findSupersededVersionUuids(cbomUuid)).thenReturn(List.of(older));
        when(policyProvider.current()).thenReturn(CbomSyncPolicy.DEFAULTS);

        dispatcher.dispatchCbom(cbomUuid);

        InOrder order = inOrder(detachService, producer);
        order.verify(detachService).withdrawWaiting(older, CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE);
        order.verify(producer).produceMessage(any());
    }

    private void givenRow(boolean synced, List<UUID> assetUuids) {
        InventoryEventOutbox row = new InventoryEventOutbox();
        row.setCbomUuid(cbomUuid);
        row.setCbomSynced(synced);
        row.setAssetUuids(assetUuids);
        when(writer.claim(eq(cbomUuid), any())).thenReturn(1);
        when(repository.findById(cbomUuid)).thenReturn(Optional.of(row));
    }

    private void givenCbom() {
        Cbom cbom = new Cbom();
        cbom.setUuid(cbomUuid);
        cbom.setSource("scanner");
        cbom.setTotalAssetsCount(2);
        when(cboms.findById(cbomUuid)).thenReturn(Optional.of(cbom));
    }

    private static CryptoAsset asset(UUID uuid) {
        CryptoAsset asset = new CryptoAsset();
        asset.setUuid(uuid);
        asset.setPqcVerdict(PqcVerdict.READY);
        asset.setInputRevision(1L);
        asset.setPqcEvaluatedRevision(1L);
        OffsetDateTime now = OffsetDateTime.now();
        asset.setUpdated(now);
        asset.setPqcEvaluatedAt(now);
        return asset;
    }
}
