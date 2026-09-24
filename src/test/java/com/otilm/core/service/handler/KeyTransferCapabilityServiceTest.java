package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.key.KeyTransferCapabilityDto;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyTransferCapabilityServiceTest {

    private static final Map<KeyRequestType, Set<KeyAlgorithm>> RSA_KEY_PAIRS = Map
            .of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA));

    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final KeyTransferCapabilityWriter writer = mock(KeyTransferCapabilityWriter.class);
    private final TokenProfileRepository profiles = mock(TokenProfileRepository.class);
    private final KeyTransferCapabilityService service = new KeyTransferCapabilityService(
            new ConnectorCapabilityService(), adapters, writer, profiles);

    @Test
    void exportableKeyTypes_answersFromTheRecordWithoutAskingTheConnector() throws Exception {
        // given
        TokenProfileFullModel profile = profile(exportingToken(), RSA_KEY_PAIRS);

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> exportable = service.exportableKeyTypes(profile);

        // then
        assertEquals(Optional.of(RSA_KEY_PAIRS), exportable);
        verifyNoInteractions(adapters, writer);
    }

    @Test
    void exportableKeyTypes_asksTheConnectorAndRecordsTheAnswerWhenThereIsNone() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel unknown = profile(token, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(unknown)).thenReturn(answer);
        when(writer.recordAnswer(unknown.uuid(), unknown.exportableKeyTypesRevision(), answer))
                .thenReturn(Optional.of(profile(token, RSA_KEY_PAIRS)));

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> exportable = service.exportableKeyTypes(unknown);

        // then
        assertEquals(Optional.of(RSA_KEY_PAIRS), exportable);
    }

    @Test
    void exportableKeyTypes_hasNoAnswerWhenTheProfileChangedWhileTheConnectorWasAsked() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel unknown = profile(token, null);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(unknown)).thenReturn(List.of());
        when(writer.recordAnswer(unknown.uuid(), unknown.exportableKeyTypesRevision(), List.of()))
                .thenReturn(Optional.empty());

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> exportable = service.exportableKeyTypes(unknown);

        // then
        assertTrue(exportable.isEmpty());
    }

    @Test
    void exportableKeyTypes_neverAsksAConnectorThatDoesNotDeclareExport() throws Exception {
        // given
        TokenProfileFullModel profile = profile(token(List.of()), null);

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> exportable = service.exportableKeyTypes(profile);

        // then
        assertEquals(Optional.of(Map.of()), exportable);
        verifyNoInteractions(adapters, writer);
    }

    @Test
    void capabilityOf_showsUnavailableAndRecordsNothingWhileTheConnectorCannotAnswer() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel unknown = profile(token, null);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(unknown)).thenThrow(new ConnectorException("Connector is down"));

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(unknown);

        // then
        assertFalse(capability.isExportAvailable());
        verify(writer, never()).recordAnswer(any(), anyInt(), any());
    }

    @Test
    void capabilityOf_ignoresTheRecordedAnswerOnceTheConnectorStopsDeclaringExport() {
        // given
        TokenProfileFullModel profile = profile(token(List.of()), RSA_KEY_PAIRS);

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(profile);

        // then
        assertFalse(capability.isExportAvailable());
        assertTrue(capability.getExportableKeyTypes().isEmpty());
    }

    @Test
    void availabilityOf_asksADownConnectorOnceForAllItsProfiles() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel first = profile(token, null);
        TokenProfileFullModel second = profile(token, null);
        when(profiles.findFullModelsByTokenInstanceReferenceUuid(token.uuid())).thenReturn(List.of(first, second));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(any()))
                .thenThrow(new ConnectorCommunicationException("Connector is unreachable", null));

        // when
        boolean available = service.availabilityOf(token).isExportAvailable();

        // then
        assertFalse(available);
        verify(adapter, times(1)).listExportableKeyTypes(any());
    }

    @Test
    void availabilityOf_keepsAskingAfterAFailureSpecificToOneProfile() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel broken = profile(token, null);
        TokenProfileFullModel exporting = profile(token, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(profiles.findFullModelsByTokenInstanceReferenceUuid(token.uuid())).thenReturn(List.of(broken, exporting));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(broken)).thenThrow(new ConnectorException("Profile attribute is invalid"));
        when(adapter.listExportableKeyTypes(exporting)).thenReturn(answer);
        when(writer.recordAnswer(exporting.uuid(), exporting.exportableKeyTypesRevision(), answer))
                .thenReturn(Optional.of(profile(token, RSA_KEY_PAIRS)));

        // when
        boolean available = service.availabilityOf(token).isExportAvailable();

        // then
        assertTrue(available);
    }

    @Test
    void availabilityOf_stillReadsRecordedAnswersAfterTheConnectorFails() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel unknown = profile(token, null);
        TokenProfileFullModel recorded = profile(token, RSA_KEY_PAIRS);
        when(profiles.findFullModelsByTokenInstanceReferenceUuid(token.uuid())).thenReturn(List.of(unknown, recorded));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(unknown))
                .thenThrow(new ConnectorCommunicationException("Connector is unreachable", null));

        // when
        boolean available = service.availabilityOf(token).isExportAvailable();

        // then
        assertTrue(available);
    }

    private static ImmutableTokenInstanceFullModel exportingToken() {
        return token(List.of(FeatureFlag.KEY_EXPORT));
    }

    private static ImmutableTokenInstanceFullModel token(List<FeatureFlag> features) {
        ImmutableConnectorInterface connectorInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", features);
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), UUID.randomUUID().toString(), "token",
                TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(), "connector", connectorInterface.uuid(),
                connectorInterface, Set.of());
    }

    private static TokenProfileFullModel profile(ImmutableTokenInstanceFullModel token,
            Map<KeyRequestType, Set<KeyAlgorithm>> exportableKeyTypes) {
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(), token, token.connectorUuid(), exportableKeyTypes, 0);
    }
}
