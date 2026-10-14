package com.otilm.core.events.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.EventException;
import com.otilm.api.model.common.events.data.CbomSyncedEventData;
import com.otilm.api.model.common.events.data.CryptoAssetPqcNotReadyEventData;
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
import com.otilm.core.evaluator.CbomTriggerEvaluator;
import com.otilm.core.evaluator.CryptoAssetTriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.messaging.model.EventMessage;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InventoryEventHandlerTest {

    @Test
    void notReadyContextPreservesTheCapturedTransitionAfterTheLiveAssetChanges() throws Exception {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        CryptoAssetPqcNotReadyEventHandler handler = assetHandler(repository, mock(CryptoAssetTriggerEvaluator.class));
        CryptoAsset asset = asset(UUID.randomUUID());
        asset.setName("updated name");
        asset.setPqcVerdict(PqcVerdict.READY);
        when(repository.findByUuid(any())).thenReturn(Optional.of(asset));
        CryptoAssetPqcNotReadyEventData captured = snapshot(asset.getUuid());
        UUID userUuid = UUID.randomUUID();
        EventMessage message = CryptoAssetPqcNotReadyEventHandler.constructEventMessage(captured, userUuid);

        EventContext<CryptoAsset> context = handler.prepareContext(message);

        assertThat(context.getResourceObjects()).containsExactly(asset);
        CryptoAssetPqcNotReadyEventData data = (CryptoAssetPqcNotReadyEventData) context
                .getResourceObjectsEventData()
                .getFirst();
        assertThat(data.getName()).isEqualTo("RSA-2048");
        assertThat(data.getAlgorithmFamily()).isEqualTo("RSA");
        assertThat(data.getPqcRuleId()).isEqualTo("RSA_NOT_READY");
        assertThat(data.getPqcReason()).isEqualTo("RSA is vulnerable to quantum attacks");
        assertThat(data.getPreviousVerdict()).isEqualTo(PqcVerdict.READY);
        assertThat(asset.getPqcVerdict()).isEqualTo(PqcVerdict.READY);
        assertThat(message.getObjectUuid()).isEqualTo(asset.getUuid());
        assertThat(message.getUserUuid()).isEqualTo(userUuid);
        assertThat(message.getOverrideResource()).isNull();
        assertThat(message.getOverrideObjectUuid()).isNull();
    }

    @Test
    void firstAssessmentKeepsTheAbsentPreviousVerdict() throws Exception {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        CryptoAssetPqcNotReadyEventHandler handler = assetHandler(repository, mock(CryptoAssetTriggerEvaluator.class));
        CryptoAsset asset = asset(UUID.randomUUID());
        asset.setPqcVerdict(PqcVerdict.NOT_READY);
        when(repository.findByUuid(any())).thenReturn(Optional.of(asset));
        CryptoAssetPqcNotReadyEventData captured = snapshot(asset.getUuid());
        captured.setPreviousVerdict(null);

        EventContext<CryptoAsset> context = handler
                .prepareContext(CryptoAssetPqcNotReadyEventHandler.constructEventMessage(captured, null));

        assertThat(((CryptoAssetPqcNotReadyEventData) context.getResourceObjectsEventData().getFirst())
                .getPreviousVerdict()).isNull();
    }

    @Test
    void assetDeletedBeforeConsumptionIsSkipped() throws Exception {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        CryptoAssetTriggerEvaluator evaluator = mock(CryptoAssetTriggerEvaluator.class);
        CryptoAssetPqcNotReadyEventHandler handler = assetHandler(repository, evaluator);
        EventHistoryRepository histories = mock(EventHistoryRepository.class);
        handler.setEventHistoryRepository(histories);
        when(repository.findByUuid(any())).thenReturn(Optional.empty());

        handler
                .handleEvent(
                        CryptoAssetPqcNotReadyEventHandler.constructEventMessage(snapshot(UUID.randomUUID()), null));

        verifyNoInteractions(evaluator, histories);
    }

    @Test
    void notReadyMessageEvaluatesItsAssetAndFinishesTheEventHistory() throws Exception {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        CryptoAssetTriggerEvaluator evaluator = mock(CryptoAssetTriggerEvaluator.class);
        CryptoAssetPqcNotReadyEventHandler handler = assetHandler(repository, evaluator);
        Trigger trigger = new Trigger();
        trigger.setName("Assign quantum migration owner");
        trigger.setResource(Resource.CRYPTO_ASSET);
        TriggerAssociation association = new TriggerAssociation();
        association.setTrigger(trigger);
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        when(associations.findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(any(), any(), any()))
                .thenReturn(List.of(association));
        handler.setTriggerAssociationRepository(associations);
        EventHistoryRepository histories = mock(EventHistoryRepository.class);
        when(histories.save(any(EventHistory.class))).thenAnswer(call -> call.getArgument(0));
        handler.setEventHistoryRepository(histories);
        CryptoAsset asset = asset(UUID.randomUUID());
        when(repository.findByUuid(any())).thenReturn(Optional.of(asset));

        handler.handleEvent(CryptoAssetPqcNotReadyEventHandler.constructEventMessage(snapshot(asset.getUuid()), null));

        ArgumentCaptor<Object> payload = ArgumentCaptor.forClass(Object.class);
        verify(evaluator).evaluateTrigger(any(), any(), any(), any(), payload.capture(), any(), any());
        assertThat(((CryptoAssetPqcNotReadyEventData) payload.getValue()).getPreviousVerdict())
                .isEqualTo(PqcVerdict.READY);
        ArgumentCaptor<EventHistory> recorded = ArgumentCaptor.forClass(EventHistory.class);
        verify(histories, times(2)).save(recorded.capture());
        assertThat(recorded.getAllValues())
                .allMatch(history -> history.getStatus() == EventStatus.FINISHED
                        && history.getEvent() == ResourceEvent.CRYPTO_ASSET_PQC_NOT_READY);
    }

    @Test
    void mismatchedSnapshotIsRejectedBeforeRepositoryAccess() {
        CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
        CryptoAssetPqcNotReadyEventHandler handler = assetHandler(repository, mock(CryptoAssetTriggerEvaluator.class));
        EventMessage message = new EventMessage(ResourceEvent.CRYPTO_ASSET_PQC_NOT_READY, Resource.CRYPTO_ASSET,
                UUID.randomUUID(), snapshot(UUID.randomUUID()));

        assertThatThrownBy(() -> handler.prepareContext(message)).isInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(repository);
    }

    @Test
    void cbomContextReadsTheSyncedCbomWithoutAnyAssetPayload() throws Exception {
        CbomRepository repository = mock(CbomRepository.class);
        CbomSyncedEventHandler handler = new CbomSyncedEventHandler(repository, mock(CbomTriggerEvaluator.class));
        handler.setTriggerAssociationRepository(emptyAssociations());
        Cbom cbom = new Cbom();
        cbom.setUuid(UUID.randomUUID());
        cbom.setSerialNumber("urn:uuid:document");
        cbom.setVersion(2);
        cbom.setSource("scanner");
        cbom.setTotalAssetsCount(4);
        when(repository.findByUuid(any())).thenReturn(Optional.of(cbom));
        EventMessage message = CbomSyncedEventHandler.constructEventMessage(cbom.getUuid(), null);

        handler.handleEvent(message);

        CbomSyncedEventData data = handler.getEventData(cbom, message.getData());
        assertThat(data.getCbomUuid()).isEqualTo(cbom.getUuid());
        assertThat(data.getSerialNumber()).isEqualTo("urn:uuid:document");
        assertThat(data.getVersion()).isEqualTo(2);
        assertThat(data.getSource()).isEqualTo("scanner");
        assertThat(data.getTotalAssets()).isEqualTo(4);
        assertThat(message.getData()).isNull();
    }

    @Test
    void cbomRepositoryFailureStillEscapes() {
        CbomRepository repository = mock(CbomRepository.class);
        CbomSyncedEventHandler handler = new CbomSyncedEventHandler(repository, mock(CbomTriggerEvaluator.class));
        DataAccessResourceFailureException unavailable = new DataAccessResourceFailureException("Database unavailable");
        when(repository.findByUuid(any())).thenThrow(unavailable);

        assertThatThrownBy(
                () -> handler.handleEvent(CbomSyncedEventHandler.constructEventMessage(UUID.randomUUID(), null)))
                .isSameAs(unavailable);
    }

    @Test
    void deletedCbomRetainsTheStandardMissingResourceFailure() {
        CbomRepository repository = mock(CbomRepository.class);
        CbomSyncedEventHandler handler = new CbomSyncedEventHandler(repository, mock(CbomTriggerEvaluator.class));
        when(repository.findByUuid(any())).thenReturn(Optional.empty());

        assertThatThrownBy(
                () -> handler.handleEvent(CbomSyncedEventHandler.constructEventMessage(UUID.randomUUID(), null)))
                .isInstanceOf(EventException.class);
    }

    private static CryptoAssetPqcNotReadyEventHandler assetHandler(CryptoAssetRepository repository,
            CryptoAssetTriggerEvaluator evaluator) {
        CryptoAssetPqcNotReadyEventHandler handler = new CryptoAssetPqcNotReadyEventHandler(repository, evaluator);
        handler.setObjectMapper(new ObjectMapper());
        handler.setTriggerAssociationRepository(emptyAssociations());
        return handler;
    }

    private static TriggerAssociationRepository emptyAssociations() {
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        when(associations.findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(any(), any(), any()))
                .thenReturn(List.of());
        return associations;
    }

    private static CryptoAssetPqcNotReadyEventData snapshot(UUID uuid) {
        CryptoAssetPqcNotReadyEventData data = new CryptoAssetPqcNotReadyEventData();
        data.setCryptoAssetUuid(uuid);
        data.setAssetType(CryptographicAssetType.ALGORITHM);
        data.setName("RSA-2048");
        data.setAlgorithmFamily("RSA");
        data.setPqcRuleId("RSA_NOT_READY");
        data.setPqcReason("RSA is vulnerable to quantum attacks");
        data.setPreviousVerdict(PqcVerdict.READY);
        return data;
    }

    private static CryptoAsset asset(UUID uuid) {
        CryptoAsset asset = new CryptoAsset();
        asset.setUuid(uuid);
        asset.setAssetType(CryptographicAssetType.ALGORITHM);
        return asset;
    }
}
