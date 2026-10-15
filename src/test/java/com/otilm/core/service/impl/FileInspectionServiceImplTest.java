package com.otilm.core.service.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectedEntryDto;
import com.otilm.api.model.client.inspection.InspectionRequestDto;
import com.otilm.api.model.client.inspection.InspectionResponseDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.core.container.Container;
import com.otilm.core.container.ContainerReader;
import com.otilm.core.container.KeyEntry;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.KeyTransfer;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyTransferCapabilityService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The inspection through the real key import gates, with the connector and the database left out. */
class FileInspectionServiceImplTest {

    private static final String UNANSWERED = "The connector of token profile importer did not answer what the profile imports. Try again.";

    private final AuthorizationEnforcer authorizationEnforcer = mock(AuthorizationEnforcer.class);
    private final TokenProfileRepository profiles = mock(TokenProfileRepository.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final KeyTransferCapabilityWriter writer = mock(KeyTransferCapabilityWriter.class);
    private final ContainerReader containerReader = mock(ContainerReader.class);
    private final FileInspectionServiceImpl service = new FileInspectionServiceImpl(authorizationEnforcer,
            new KeyImportGates(authorizationEnforcer, profiles,
                    new KeyTransferCapabilityService(new ConnectorCapabilityService(), adapters, writer,
                            mock(TokenInstanceReferenceRepository.class), profiles),
                    mock(CryptographicKeyWriter.class)),
            containerReader);

    /** A file holding keys of several kinds asks the connector what the profile imports once, not once per kind. */
    @Test
    void inspect_asksTheConnectorOnceForKeysOfTwoKinds() throws Exception {
        // given
        TokenProfileFullModel profile = namedProfile();
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(adapter.listImportableKeyTypes(profile)).thenReturn(answer);
        when(writer.recordAnswer(profile.uuid(), profile.keyTypesRevision(), KeyTransfer.IMPORT, answer))
                .thenReturn(Optional.of(recorded(profile, Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)))));
        when(containerReader.read(any(), any()))
                .thenReturn(new Container("digest",
                        List
                                .of(key(KeyAlgorithm.RSA, new byte[]{1}), key(KeyAlgorithm.ECDSA, new byte[]{2}),
                                        key(KeyAlgorithm.RSA, new byte[]{3}))));
        InspectionRequestDto request = request(profile.uuid().toString());

        // when
        InspectionResponseDto inspection = service.inspect(request);

        // then
        assertThat(inspection.getEntries())
                .extracting(InspectedEntryDto::getImportable, InspectedEntryDto::getNotImportableReason)
                .containsExactly(tuple(true, null),
                        tuple(false, "Token profile importer does not import the ECDSA algorithm for a key pair."),
                        tuple(true, null));
        verify(adapter).listImportableKeyTypes(profile);
        verify(writer).recordAnswer(profile.uuid(), profile.keyTypesRevision(), KeyTransfer.IMPORT, answer);
    }

    /** A connector that does not answer leaves every key not importable, with one warning for the inspection. */
    @Test
    void inspect_reportsKeysOfTwoKindsAsNotImportableWithOneWarningWhenTheConnectorDoesNotAnswer() throws Exception {
        // given
        TokenProfileFullModel profile = namedProfile();
        when(adapter.listImportableKeyTypes(profile))
                .thenThrow(new ConnectorCommunicationException("The connector is not reachable.", null));
        when(containerReader.read(any(), any()))
                .thenReturn(new Container("digest",
                        List.of(key(KeyAlgorithm.RSA, new byte[]{1}), key(KeyAlgorithm.ECDSA, new byte[]{2}))));
        InspectionRequestDto request = request(profile.uuid().toString());
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(FileInspectionServiceImpl.class);
        logs.start();
        logger.addAppender(logs);

        // when
        InspectionResponseDto inspection;
        try {
            inspection = service.inspect(request);
        } finally {
            logger.detachAppender(logs);
        }

        // then
        assertThat(inspection.getEntries())
                .extracting(InspectedEntryDto::getImportable, InspectedEntryDto::getNotImportableReason)
                .containsExactly(tuple(false, UNANSWERED), tuple(false, UNANSWERED));
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.WARN).hasSize(1);
        verify(adapter).listImportableKeyTypes(profile);
    }

    @Test
    void inspect_overwritesTheFileItReadAndTheKeysOfItsEntries() throws Exception {
        // given
        byte[] keyFile = {1, 2, 3};
        ArgumentCaptor<byte[]> read = ArgumentCaptor.forClass(byte[].class);
        when(containerReader.read(read.capture(), any()))
                .thenReturn(new Container("digest", List.of(key(KeyAlgorithm.RSA, keyFile))));
        InspectionRequestDto request = request(null);

        // when
        service.inspect(request);

        // then
        assertThat(read.getValue()).hasSize(4).containsOnly(0);
        assertThat(keyFile).containsOnly(0);
    }

    @Test
    void inspect_overwritesTheFileItReadWhenTheFileIsRefused() {
        // given
        ArgumentCaptor<byte[]> read = ArgumentCaptor.forClass(byte[].class);
        when(containerReader.read(read.capture(), any()))
                .thenThrow(new ValidationException(ValidationError.create("refused")));
        InspectionRequestDto request = request(null);

        // when
        assertThrows(ValidationException.class, () -> service.inspect(request));

        // then
        assertThat(read.getValue()).hasSize(4).containsOnly(0);
    }

    /** A profile that imports keys and has no answer recorded yet, which the caller names and may use. */
    private TokenProfileFullModel namedProfile() throws Exception {
        ImmutableConnectorInterface connectorInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT));
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(),
                UUID.randomUUID().toString(), "token", TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(),
                "connector", connectorInterface.uuid(), connectorInterface, Set.of());
        TokenProfileFullModel profile = new ImmutableTokenProfileFullModel(UUID.randomUUID(), "importer", null,
                token.name(), token.uuid(), true, List.of(), token, token.connectorUuid(), null, null, 0);
        TokenProfile entity = new TokenProfile();
        entity.setUuid(profile.uuid());
        entity.setTokenInstanceReferenceUuid(token.uuid());
        when(profiles.findByUuid(profile.uuid())).thenReturn(Optional.of(entity));
        when(profiles.findFullModelByUuidAndTokenInstanceReferenceUuid(profile.uuid(), token.uuid()))
                .thenReturn(Optional.of(profile));
        when(adapters.forToken(token)).thenReturn(adapter);
        return profile;
    }

    /** The profile as it stands once the connector's answer is recorded on it. */
    private static TokenProfileFullModel recorded(TokenProfileFullModel profile,
            Map<KeyRequestType, Set<KeyAlgorithm>> importableKeyTypes) {
        return new ImmutableTokenProfileFullModel(profile.uuid(), profile.name(), null, profile.tokenInstanceName(),
                profile.tokenInstanceReferenceUuid(), true, List.of(), profile.tokenInstance(), profile.connectorUuid(),
                null, importableKeyTypes, profile.keyTypesRevision());
    }

    private static KeyEntry key(KeyAlgorithm algorithm, byte[] keyFile) {
        return new KeyEntry(UUID.randomUUID().toString(), null, keyFile,
                new KeyDescription(KeyRequestType.KEY_PAIR, algorithm, 256, new byte[]{4}, null), null, List.of(),
                false);
    }

    private static InspectionRequestDto request(String tokenProfileUuid) {
        InspectionRequestDto request = new InspectionRequestDto();
        request.setFile(new UploadedFile(new byte[]{5, 6, 7, 8}));
        request.setTokenProfileUuid(tokenProfileUuid);
        return request;
    }
}
