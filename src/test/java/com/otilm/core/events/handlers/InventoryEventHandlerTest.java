package com.otilm.core.events.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.EventException;
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
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataAccessResourceFailureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InventoryEventHandlerTest {

    @Test
    void anUntypedAssetDoesNotExposeItsStoredRoutingTierInEventData() {
        CryptoAsset asset = asset(UUID.randomUUID());
        asset.setAssetType(CryptographicAssetType.UNROUTABLE);
        asset.setPqcVerdict(PqcVerdict.UNKNOWN);

        CryptoAssetAddedEventData snapshot = CryptoAssetAddedEventHandler.snapshot(asset, UUID.randomUUID());

        assertThat(snapshot.getAssetType()).isNull();
        var json = new ObjectMapper().valueToTree(snapshot);
        assertThat(json.has("assetType")).isFalse();
        assertThat(json.get("pqcVerdict").asText()).isEqualTo("unknown");
        assertThat(asset.getAssetType()).isEqualTo(CryptographicAssetType.UNROUTABLE);
    }

    @ParameterizedTest
    @CsvSource({
            "ALGORITHM, algorithm",
            "CERTIFICATE, certificate",
            "PROTOCOL, protocol",
            "RELATED_CRYPTO_MATERIAL, related-crypto-material"})
    void aTypedAssetKeepsItsPublicTypeInEventData(CryptographicAssetType type, String expectedType) {
        CryptoAsset asset = asset(UUID.randomUUID());
        asset.setAssetType(type);
        asset.setPqcVerdict(PqcVerdict.READY);

        var json = new ObjectMapper().valueToTree(CryptoAssetAddedEventHandler.snapshot(asset, UUID.randomUUID()));

        assertThat(json.get("assetType").asText()).isEqualTo(expectedType);
        assertThat(json.get("pqcVerdict").asText()).isEqualTo("ready");
    }

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
    void cbomTriggersRunAfterATerminalAssetEventFailure() throws Exception {
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
        doThrow(new EventException(ResourceEvent.CRYPTO_ASSET_ADDED, "Asset was deleted"))
                .when(assets)
                .handleEvent(any(EventMessage.class));

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

    @Test
    void assetRepositoryFailureEscapesWithoutRunningCbomTriggers() {
        CryptoAssetRepository assets = mock(CryptoAssetRepository.class);
        CryptoAssetAddedEventHandler assetHandler = new CryptoAssetAddedEventHandler(assets,
                mock(TriggerEvaluator.class));
        assetHandler.setObjectMapper(new ObjectMapper());
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        when(associations.findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(any(), any(), any()))
                .thenReturn(List.of());
        assetHandler.setTriggerAssociationRepository(associations);
        DataAccessResourceFailureException unavailable = new DataAccessResourceFailureException("Database unavailable");
        when(assets.findByUuid(any())).thenThrow(unavailable);
        CbomRepository cboms = mock(CbomRepository.class);
        CbomSyncedEventHandler handler = new CbomSyncedEventHandler(cboms, mock(TriggerEvaluator.class), assetHandler);
        handler.setObjectMapper(new ObjectMapper());
        handler.setTriggerAssociationRepository(associations);
        when(cboms.findByUuid(any())).thenReturn(Optional.empty());
        UUID cbomUuid = UUID.randomUUID();
        CbomSyncedEventData cbom = new CbomSyncedEventData();
        cbom.setCbomUuid(cbomUuid);
        EventMessage message = CbomSyncedEventHandler
                .constructEventMessage(cbomUuid, cbom,
                        List.of(CryptoAssetAddedEventHandler.snapshot(asset(UUID.randomUUID()), cbomUuid)), null);

        assertThatThrownBy(() -> handler.handleEvent(message)).isSameAs(unavailable);

        verifyNoInteractions(cboms);
    }

    @ParameterizedTest
    @MethodSource("malformedCbomPayloads")
    void malformedCbomPayloadIsRejectedBeforeRepositoryAccess(CbomSyncedEventPayload payload) {
        CbomRepository cboms = mock(CbomRepository.class);
        CryptoAssetRepository assets = mock(CryptoAssetRepository.class);
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        CryptoAssetAddedEventHandler assetHandler = new CryptoAssetAddedEventHandler(assets,
                mock(TriggerEvaluator.class));
        assetHandler.setObjectMapper(new ObjectMapper());
        assetHandler.setTriggerAssociationRepository(associations);
        CbomSyncedEventHandler handler = new CbomSyncedEventHandler(cboms, mock(TriggerEvaluator.class), assetHandler);
        handler.setObjectMapper(new ObjectMapper());
        handler.setTriggerAssociationRepository(associations);
        EventMessage message = new EventMessage(ResourceEvent.CBOM_SYNCED, Resource.CBOM, UUID.randomUUID(), payload);

        assertThatThrownBy(() -> handler.handleEvent(message)).isInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(cboms, assets, associations);
    }

    private static Stream<CbomSyncedEventPayload> malformedCbomPayloads() {
        CbomSyncedEventData cbom = new CbomSyncedEventData();
        return Stream
                .of(null, new CbomSyncedEventPayload(cbom, null), new CbomSyncedEventPayload(null, List.of()),
                        new CbomSyncedEventPayload(cbom, Collections.singletonList(null)),
                        new CbomSyncedEventPayload(cbom, List.of(new CryptoAssetAddedEventData())));
    }

    @ParameterizedTest
    @MethodSource("malformedAssetPayloads")
    void malformedAssetPayloadIsRejectedBeforeRepositoryAccess(List<CryptoAssetAddedEventData> payload) {
        CryptoAssetRepository assets = mock(CryptoAssetRepository.class);
        TriggerAssociationRepository associations = mock(TriggerAssociationRepository.class);
        CryptoAssetAddedEventHandler handler = new CryptoAssetAddedEventHandler(assets, mock(TriggerEvaluator.class));
        handler.setObjectMapper(new ObjectMapper());
        handler.setTriggerAssociationRepository(associations);
        EventMessage message = new EventMessage(ResourceEvent.CRYPTO_ASSET_ADDED, Resource.CRYPTO_ASSET, null, payload);

        assertThatThrownBy(() -> handler.prepareContext(message)).isInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(assets, associations);
    }

    private static Stream<List<CryptoAssetAddedEventData>> malformedAssetPayloads() {
        return Stream
                .of(null, Collections.singletonList(null), List.of(new CryptoAssetAddedEventData()),
                        List
                                .of(CryptoAssetAddedEventHandler.snapshot(asset(UUID.randomUUID()), UUID.randomUUID()),
                                        new CryptoAssetAddedEventData()));
    }

    private static CryptoAsset asset(UUID uuid) {
        CryptoAsset asset = new CryptoAsset();
        asset.setUuid(uuid);
        asset.setAssetType(CryptographicAssetType.ALGORITHM);
        return asset;
    }
}
