package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.key.KeyTransferAvailabilityDto;
import com.otilm.api.model.core.cryptography.key.KeyTransferCapabilityDto;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.KeyTransfer;
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
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;

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
    private final TokenInstanceReferenceRepository tokens = mock(TokenInstanceReferenceRepository.class);
    private final TokenProfileRepository profiles = mock(TokenProfileRepository.class);
    private final KeyTransferCapabilityService service = new KeyTransferCapabilityService(
            new ConnectorCapabilityService(), adapters, writer, tokens, profiles);

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
        when(writer.recordAnswer(unknown.uuid(), unknown.keyTypesRevision(), KeyTransfer.EXPORT, answer))
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
        when(writer.recordAnswer(unknown.uuid(), unknown.keyTypesRevision(), KeyTransfer.EXPORT, List.of()))
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
    void importableKeyTypes_asksTheConnectorAndRecordsTheAnswerAsTheImportAnswer() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT));
        TokenProfileFullModel unknown = profile(token, null, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(unknown)).thenReturn(answer);
        when(writer.recordAnswer(unknown.uuid(), unknown.keyTypesRevision(), KeyTransfer.IMPORT, answer))
                .thenReturn(Optional.of(profile(token, null, RSA_KEY_PAIRS)));

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> importable = service.importableKeyTypes(unknown);

        // then
        assertEquals(Optional.of(RSA_KEY_PAIRS), importable);
        verify(adapter, never()).listExportableKeyTypes(any());
    }

    @Test
    void importableKeyTypes_answersFromTheRecordWithoutAskingTheConnector() throws Exception {
        // given
        TokenProfileFullModel profile = profile(token(List.of(FeatureFlag.KEY_IMPORT)), null, RSA_KEY_PAIRS);

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> importable = service.importableKeyTypes(profile);

        // then
        assertEquals(Optional.of(RSA_KEY_PAIRS), importable);
        verifyNoInteractions(adapters, writer);
    }

    @Test
    void importableKeyTypes_neverAsksAConnectorThatDeclaresExportOnly() throws Exception {
        // given
        TokenProfileFullModel profile = profile(exportingToken(), RSA_KEY_PAIRS, RSA_KEY_PAIRS);

        // when
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> importable = service.importableKeyTypes(profile);

        // then
        assertEquals(Optional.of(Map.of()), importable);
        verifyNoInteractions(adapters, writer);
    }

    @ParameterizedTest
    @MethodSource("failuresToLearnTheAnswer")
    void capabilityOf_showsUnavailableAndRecordsNothingWhileTheAnswerCannotBeLearned(Exception failure)
            throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel unknown = profile(token, null);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(unknown)).thenThrow(failure);

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(unknown);

        // then
        assertFalse(capability.isExportAvailable());
        verify(writer, never()).recordAnswer(any(), anyInt(), any(), any());
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

    @ParameterizedTest
    @MethodSource("failuresOfTheConnector")
    void availabilityOf_asksAConnectorThatCannotAnswerOnceForAllItsProfiles(ConnectorException failure)
            throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel first = profile(token, null);
        TokenProfileFullModel second = profile(token, null);
        withProfiles(token, first, second);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(any())).thenThrow(failure);

        // when
        boolean available = service.availabilityOf(token).isExportAvailable();

        // then
        assertFalse(available);
        verify(adapter, times(1)).listExportableKeyTypes(any());
    }

    @ParameterizedTest
    @MethodSource("failuresSpecificToOneProfile")
    void availabilityOf_keepsAskingAfterAFailureSpecificToOneProfile(Exception failure) throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = exportingToken();
        TokenProfileFullModel broken = profile(token, null);
        TokenProfileFullModel exporting = profile(token, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        withProfiles(token, broken, exporting);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(broken)).thenThrow(failure);
        when(adapter.listExportableKeyTypes(exporting)).thenReturn(answer);
        when(writer.recordAnswer(exporting.uuid(), exporting.keyTypesRevision(), KeyTransfer.EXPORT, answer))
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
        withProfiles(token, unknown, recorded);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listExportableKeyTypes(unknown))
                .thenThrow(new ConnectorCommunicationException("Connector is unreachable", null));

        // when
        boolean available = service.availabilityOf(token).isExportAvailable();

        // then
        assertTrue(available);
    }

    @Test
    void capabilityOf_showsWhatTheProfileImportsAndExports() {
        // given
        TokenProfileFullModel profile = profile(token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT)),
                Map.of(), RSA_KEY_PAIRS);

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(profile);

        // then
        assertTrue(capability.isImportAvailable());
        assertEquals(RSA_KEY_PAIRS, capability.getImportableKeyTypes());
        assertFalse(capability.isExportAvailable());
        assertEquals(Map.of(), capability.getExportableKeyTypes());
        verifyNoInteractions(adapters, writer);
    }

    @Test
    void capabilityOf_doesNotAskForExportOnceTheConnectorCannotBeReached() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
        TokenProfileFullModel unknown = profile(token, null, null);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(unknown))
                .thenThrow(new ConnectorCommunicationException("Connector is unreachable", null));

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(unknown);

        // then
        assertFalse(capability.isImportAvailable());
        assertFalse(capability.isExportAvailable());
        verify(adapter, never()).listExportableKeyTypes(any());
    }

    @ParameterizedTest
    @MethodSource("failuresOnTheConnectorsSide")
    void capabilityOf_stillAsksForExportAfterTheConnectorFailedToSayWhatItImports(ConnectorException failure)
            throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
        TokenProfileFullModel unknown = profile(token, null, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(unknown)).thenThrow(failure);
        when(adapter.listExportableKeyTypes(unknown)).thenReturn(answer);
        when(writer.recordAnswer(unknown.uuid(), unknown.keyTypesRevision(), KeyTransfer.EXPORT, answer))
                .thenReturn(Optional.of(profile(token, RSA_KEY_PAIRS)));

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(unknown);

        // then
        assertFalse(capability.isImportAvailable());
        assertEquals(RSA_KEY_PAIRS, capability.getExportableKeyTypes());
    }

    @ParameterizedTest
    @MethodSource("failuresOnTheConnectorsSide")
    void availabilityOf_stopsAskingOnlyForTheAnswerTheConnectorFailedToGive(ConnectorException failure)
            throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
        TokenProfileFullModel first = profile(token, null, null);
        TokenProfileFullModel second = profile(token, null, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        withProfiles(token, first, second);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(any())).thenThrow(failure);
        when(adapter.listExportableKeyTypes(first)).thenReturn(List.of());
        when(adapter.listExportableKeyTypes(second)).thenReturn(answer);
        when(writer.recordAnswer(second.uuid(), second.keyTypesRevision(), KeyTransfer.EXPORT, answer))
                .thenReturn(Optional.of(profile(token, RSA_KEY_PAIRS)));

        // when
        KeyTransferAvailabilityDto availability = service.availabilityOf(token);

        // then
        assertFalse(availability.isImportAvailable());
        assertTrue(availability.isExportAvailable());
        verify(adapter, times(1)).listImportableKeyTypes(any());
    }

    @Test
    void capabilityOf_stillShowsARecordedExportAnswerAfterTheConnectorFailed() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
        TokenProfileFullModel profile = profile(token, RSA_KEY_PAIRS, null);
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(profile))
                .thenThrow(new ConnectorCommunicationException("Connector is unreachable", null));

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(profile);

        // then
        assertTrue(capability.isExportAvailable());
        assertEquals(RSA_KEY_PAIRS, capability.getExportableKeyTypes());
    }

    @Test
    void capabilityOf_showsADisabledProfileAsImportingNothing() {
        // given
        TokenProfileFullModel disabled = disabledProfile(token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT)),
                RSA_KEY_PAIRS, RSA_KEY_PAIRS);

        // when
        KeyTransferCapabilityDto capability = service.capabilityOf(disabled);

        // then
        assertFalse(capability.isImportAvailable());
        assertEquals(Map.of(), capability.getImportableKeyTypes());
        assertEquals(RSA_KEY_PAIRS, capability.getExportableKeyTypes());
    }

    @Test
    void availabilityOf_doesNotAskWhatADisabledProfileImports() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
        withProfiles(token, disabledProfile(token, Map.of(), null));
        when(adapters.forToken(token)).thenReturn(adapter);

        // when
        boolean importAvailable = service.availabilityOf(token).isImportAvailable();

        // then
        assertFalse(importAvailable);
        verify(adapter, never()).listImportableKeyTypes(any());
    }

    @Test
    void availabilityOf_reportsImportAndExportFromDifferentProfiles() {
        // given
        ImmutableTokenInstanceFullModel token = token(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
        withProfiles(token, profile(token, Map.of(), RSA_KEY_PAIRS), profile(token, RSA_KEY_PAIRS, Map.of()));

        // when
        KeyTransferAvailabilityDto availability = service.availabilityOf(token);

        // then
        assertTrue(availability.isImportAvailable());
        assertTrue(availability.isExportAvailable());
        verifyNoInteractions(adapters, writer);
    }

    private void withProfiles(ImmutableTokenInstanceFullModel token, TokenProfileFullModel... tokenProfiles) {
        when(tokens.findFullModelByUuid(token.uuid())).thenReturn(Optional.of(token));
        when(profiles.findFullModelsByTokenInstance(token)).thenReturn(List.of(tokenProfiles));
    }

    private static Stream<ConnectorException> failuresOfTheConnector() {
        return Stream
                .concat(Stream.of(new ConnectorCommunicationException("Connector is unreachable", null)),
                        failuresOnTheConnectorsSide());
    }

    private static Stream<ConnectorException> failuresOnTheConnectorsSide() {
        return Stream
                .of(new ConnectorServerException("Connector failed", HttpStatus.INTERNAL_SERVER_ERROR),
                        problem(HttpStatus.SERVICE_UNAVAILABLE));
    }

    private static Stream<Exception> failuresSpecificToOneProfile() {
        return Stream
                .of(new ConnectorClientException("Profile attribute is invalid", HttpStatus.BAD_REQUEST),
                        problem(HttpStatus.UNPROCESSABLE_ENTITY),
                        new ValidationException("Secret the profile references is disabled"));
    }

    private static ConnectorProblemException problem(HttpStatus status) {
        ProblemDetailExtended problem = new ProblemDetailExtended();
        problem.setStatus(status.value());
        problem.setTitle(status.getReasonPhrase());
        return new ConnectorProblemException(problem);
    }

    private static Stream<Exception> failuresToLearnTheAnswer() {
        return Stream.concat(failuresOfTheConnector(), failuresSpecificToOneProfile());
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
        return profile(token, exportableKeyTypes, null);
    }

    private static TokenProfileFullModel profile(ImmutableTokenInstanceFullModel token,
            Map<KeyRequestType, Set<KeyAlgorithm>> exportableKeyTypes,
            Map<KeyRequestType, Set<KeyAlgorithm>> importableKeyTypes) {
        return profile(token, true, exportableKeyTypes, importableKeyTypes);
    }

    private static TokenProfileFullModel disabledProfile(ImmutableTokenInstanceFullModel token,
            Map<KeyRequestType, Set<KeyAlgorithm>> exportableKeyTypes,
            Map<KeyRequestType, Set<KeyAlgorithm>> importableKeyTypes) {
        return profile(token, false, exportableKeyTypes, importableKeyTypes);
    }

    private static TokenProfileFullModel profile(ImmutableTokenInstanceFullModel token, boolean enabled,
            Map<KeyRequestType, Set<KeyAlgorithm>> exportableKeyTypes,
            Map<KeyRequestType, Set<KeyAlgorithm>> importableKeyTypes) {
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(),
                enabled, List.of(), token, token.connectorUuid(), exportableKeyTypes, importableKeyTypes, 0);
    }
}
