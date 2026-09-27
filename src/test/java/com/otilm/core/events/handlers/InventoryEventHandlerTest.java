package com.otilm.core.events.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.events.data.CbomSyncedEventData;
import com.otilm.api.model.common.events.data.CryptoAssetAddedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authz.SecuredUUID;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InventoryEventHandlerTest {

    @Test
    void oneAssetMessagePreparesEveryNewAssetWithItsCbom() throws Exception {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        CryptoAssetAddedEventHandler handler = new CryptoAssetAddedEventHandler(repository,
                mock(TriggerEvaluator.class));
        handler.setObjectMapper(new ObjectMapper());
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        when(associations.findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(any(), any(), any()))
                .thenReturn(List.of());
        handler.setTriggerAssociationRepository(associations);
        UUID cbomUuid = UUID.randomUUID();
        CryptoAsset first = asset(UUID.randomUUID());
        first.setAlgorithmFamily("RSA");
        first.setPqcVerdict(PqcVerdict.NOT_READY);
        CryptoAssetAddedEventData capturedFirst = CryptoAssetAddedEventHandler.snapshot(first, cbomUuid);
        first.setPqcVerdict(PqcVerdict.READY);
        CryptoAsset second = asset(UUID.randomUUID());
        when(repository.findByUuid(argThat(id -> id != null && id.getValue().equals(first.getUuid()))))
                .thenReturn(Optional.of(first));
        when(repository.findByUuid(argThat(id -> id != null && id.getValue().equals(second.getUuid()))))
                .thenReturn(Optional.of(second));

        EventContext<CryptoAsset> context = handler
                .prepareContext(CryptoAssetAddedEventHandler
                        .constructEventMessage(cbomUuid,
                                List.of(capturedFirst, CryptoAssetAddedEventHandler.snapshot(second, cbomUuid)), null));

        assertThat(context.getResourceObjects()).containsExactly(first, second);
        assertThat(context.getResourceObjectsEventData()).hasSize(2);
        assertThat(((CryptoAssetAddedEventData) context.getResourceObjectsEventData().getFirst()).getCbomUuid())
                .isEqualTo(cbomUuid);
        CryptoAssetAddedEventData firstData = (CryptoAssetAddedEventData) context
                .getResourceObjectsEventData()
                .getFirst();
        assertThat(firstData.getAlgorithmFamily()).isEqualTo("RSA");
        assertThat(firstData.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(first.getPqcVerdict()).isEqualTo(PqcVerdict.READY);
    }

    @Test
    void bulkAssetMessageEvaluatesBothAssetsAndFinishesTheirEventHistories() throws Exception {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        TriggerEvaluator<CryptoAsset> evaluator = mock(TriggerEvaluator.class);
        CryptoAssetAddedEventHandler handler = new CryptoAssetAddedEventHandler(repository, evaluator);
        handler.setObjectMapper(new ObjectMapper());
        Trigger trigger = new Trigger();
        trigger.setName("Categorize new assets");
        trigger.setResource(Resource.CRYPTO_ASSET);
        TriggerAssociation association = new TriggerAssociation();
        association.setTrigger(trigger);
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        when(associations.findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(any(), any(), any()))
                .thenReturn(List.of());
        when(associations
                .findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(eq(ResourceEvent.CRYPTO_ASSET_ADDED),
                        isNull(), isNull()))
                .thenReturn(List.of(association));
        handler.setTriggerAssociationRepository(associations);
        EventHistoryRepository histories = mock(EventHistoryRepository.class);
        when(histories.save(any(EventHistory.class))).thenAnswer(call -> call.getArgument(0));
        handler.setEventHistoryRepository(histories);
        CryptoAsset first = asset(UUID.randomUUID());
        CryptoAsset second = asset(UUID.randomUUID());
        when(repository.findByUuid(any())).thenAnswer(call -> {
            UUID uuid = ((SecuredUUID) call.getArgument(0)).getValue();
            return Optional.of(uuid.equals(first.getUuid()) ? first : second);
        });

        UUID cbomUuid = UUID.randomUUID();
        handler
                .handleEvent(CryptoAssetAddedEventHandler
                        .constructEventMessage(cbomUuid,
                                List
                                        .of(CryptoAssetAddedEventHandler.snapshot(first, cbomUuid),
                                                CryptoAssetAddedEventHandler.snapshot(second, cbomUuid)),
                                null));

        ArgumentCaptor<CryptoAsset> evaluated = ArgumentCaptor.forClass(CryptoAsset.class);
        verify(evaluator, times(2)).evaluateTrigger(any(), any(), evaluated.capture(), any(), any(), any(), any());
        assertThat(evaluated.getAllValues()).containsExactly(first, second);
        ArgumentCaptor<EventHistory> recorded = ArgumentCaptor.forClass(EventHistory.class);
        verify(histories, times(4)).save(recorded.capture());
        assertThat(recorded.getAllValues()).allMatch(history -> history.getStatus() == EventStatus.FINISHED);
        assertThat(recorded.getAllValues()).allMatch(history -> history.getEvent() == ResourceEvent.CRYPTO_ASSET_ADDED);
    }

    @Test
    void cbomTriggersRunAfterAssetTriggersEvenIfAssetHandlingFails() throws Exception {
        CbomRepository repository = mock(CbomRepository.class);
        CryptoAssetAddedEventHandler assets = mock(CryptoAssetAddedEventHandler.class);
        CbomSyncedEventHandler handler = new CbomSyncedEventHandler(repository, mock(TriggerEvaluator.class), assets);
        handler.setObjectMapper(new ObjectMapper());
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        when(associations.findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(any(), any(), any()))
                .thenReturn(List.of());
        handler.setTriggerAssociationRepository(associations);
        UUID cbomUuid = UUID.randomUUID();
        UUID assetUuid = UUID.randomUUID();
        Cbom cbom = new Cbom();
        cbom.setUuid(cbomUuid);
        cbom.setSource("scanner");
        cbom.setTotalAssetsCount(2);
        CbomSyncedEventData capturedCbom = CbomSyncedEventHandler.snapshot(cbom);
        cbom.setSource("updated later");
        when(repository.findByUuid(argThat(id -> id != null && id.getValue().equals(cbomUuid))))
                .thenReturn(Optional.of(cbom));
        doThrow(new IllegalStateException("trigger failed")).when(assets).handleEvent(any(EventMessage.class));

        handler
                .handleEvent(CbomSyncedEventHandler
                        .constructEventMessage(cbomUuid, capturedCbom,
                                List.of(CryptoAssetAddedEventHandler.snapshot(asset(assetUuid), cbomUuid)), null));

        CbomSyncedEventData data = handler.getEventData(cbom, new CbomSyncedEventPayload(capturedCbom, List.of()));
        assertThat(data.getSource()).isEqualTo("scanner");
        assertThat(data.getTotalAssets()).isEqualTo(2);

        InOrder order = inOrder(assets, repository);
        order.verify(assets).handleEvent(any(EventMessage.class));
        order.verify(repository).findByUuid(argThat(id -> id != null && id.getValue().equals(cbomUuid)));
        verify(repository).findByUuid(argThat(id -> id != null && id.getValue().equals(cbomUuid)));
    }

    private static CryptoAsset asset(UUID uuid) {
        CryptoAsset asset = new CryptoAsset();
        asset.setUuid(uuid);
        asset.setAssetType(CryptographicAssetType.ALGORITHM);
        return asset;
    }
}
