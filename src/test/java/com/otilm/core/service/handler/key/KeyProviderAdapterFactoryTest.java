package com.otilm.core.service.handler.key;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.client.CryptographyV2ApiClients;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyProviderAdapterFactoryTest {

    private ConnectorInternalService connectorService;
    private ConnectorApiFactory clients;
    private KeyProviderAdapterFactory factory;
    private ImmutableConnectorFullModel connector;

    @BeforeEach
    void setUp() throws Exception {
        connectorService = mock(ConnectorInternalService.class);
        clients = mock(ConnectorApiFactory.class);
        factory = new KeyProviderAdapterFactory(connectorService, clients, mock(AttributeEngine.class),
                mock(OperationAttributeResolver.class), mock(OutboundSecretContainment.class),
                mock(CryptographyV2ApiClients.class), new ConnectorCapabilityService());
        connector = new ImmutableConnectorFullModel(UUID.randomUUID(), "provider", ConnectorVersion.V2,
                "http://connector.test", null, List.of(), null, null, List.of(cryptographyInterface("v2")), List.of());
        when(connectorService.getConnectorFullModelForApiClient(connector.uuid())).thenReturn(connector);
        when(connectorService.getConnectorForApiClient(connector.uuid())).thenReturn(connector);
    }

    @Test
    void forToken_selectsV1_whenLegacyTokenConnectorAdvertisesV2() throws Exception {
        // given
        ImmutableTokenInstanceFullModel legacyToken = token(null);

        // when
        KeyProviderAdapter adapter = factory.forToken(legacyToken);

        // then
        assertInstanceOf(KeyProviderV1Adapter.class, adapter);
        verify(clients).getKeyManagementApiClient(connector);
    }

    @Test
    void forToken_selectsV2_forPersistedCryptographyInterface() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(connector.connectorInterfaces().getFirst());

        // when
        KeyProviderAdapter adapter = factory.forToken(token);

        // then
        assertInstanceOf(KeyProviderV2Adapter.class, adapter);
        verify(clients).getKeyManagementApiClientV2(connector);
        verify(connectorService).getConnectorFullModelForApiClient(token.connectorUuid());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsupportedInterfaces")
    void forToken_rejectsUnsupportedInterface(ImmutableConnectorInterface connectorInterface) {
        // given
        ImmutableTokenInstanceFullModel token = token(connectorInterface);

        // when
        Executable select = () -> factory.forToken(token);

        // then
        assertThrows(UnsupportedCryptographyProviderVersionException.class, select);
        verifyNoInteractions(clients);
    }

    @Test
    void forToken_rejectsMissingToken() {
        // given
        ImmutableTokenInstanceFullModel missingToken = null;

        // when
        Executable select = () -> factory.forToken(missingToken);

        // then
        assertThrows(NullPointerException.class, select);
        verifyNoInteractions(connectorService, clients);
    }

    @Test
    void forToken_rejectsMissingConnector() {
        // given
        String missingConnectorName = "deleted provider";
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token",
                TokenInstanceStatus.UNKNOWN, null, null, missingConnectorName, null, null, Set.of());

        // when
        Executable select = () -> factory.forToken(token);

        // then
        NotFoundException exception = assertThrows(NotFoundException.class, select);
        assertTrue(exception.getMessage().contains(missingConnectorName));
        verifyNoInteractions(connectorService, clients);
    }

    @Test
    void forToken_propagatesMissingConnector() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = token(null);
        NotFoundException missingConnector = new NotFoundException(Connector.class, connector.uuid());
        when(connectorService.getConnectorFullModelForApiClient(connector.uuid())).thenThrow(missingConnector);

        // when
        Executable select = () -> factory.forToken(token);

        // then
        assertSame(missingConnector, assertThrows(NotFoundException.class, select));
        verifyNoInteractions(clients);
    }

    @Test
    void forKeyItem_selectsV1_forItemWithoutInterface() throws Exception {
        // given
        CryptographicKeyItemOperationModel item = keyItem(null, null);

        // when
        KeyProviderAdapter adapter = factory.forKeyItem(item);

        // then
        assertInstanceOf(KeyProviderV1Adapter.class, adapter);
        verify(clients).getKeyManagementApiClient(connector);
    }

    @Test
    void forKeyItem_selectsV2_forCryptographyV2Interface() throws Exception {
        // given
        CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");

        // when
        KeyProviderAdapter adapter = factory.forKeyItem(item);

        // then
        assertInstanceOf(KeyProviderV2Adapter.class, adapter);
        verify(clients).getKeyManagementApiClientV2(connector);
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource(value = {"DISCOVERY,v2", "CRYPTOGRAPHY,", "CRYPTOGRAPHY,v3", "CRYPTOGRAPHY,v1"})
    void forKeyItem_rejectsUnsupportedInterface(ConnectorInterface code, String version) {
        // given
        CryptographicKeyItemOperationModel item = keyItem(code, version);

        // when
        Executable select = () -> factory.forKeyItem(item);

        // then
        assertThrows(UnsupportedCryptographyProviderVersionException.class, select);
        verifyNoInteractions(clients);
    }

    private CryptographicKeyItemOperationModel keyItem(ConnectorInterface code, String version) {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.SIGN), null,
                new RemoteKeyReference.UuidReference(UUID.randomUUID()), connector.uuid(), UUID.randomUUID(),
                UUID.randomUUID(), code, version);
    }

    private ImmutableTokenInstanceFullModel token(ImmutableConnectorInterface connectorInterface) {
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.UNKNOWN, null,
                connector.uuid(), connector.name(), connectorInterface == null ? null : connectorInterface.uuid(),
                connectorInterface, Set.of());
    }

    private static ImmutableConnectorInterface cryptographyInterface(String version) {
        return new ImmutableConnectorInterface(UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, version, List.of());
    }

    private static Stream<Arguments> unsupportedInterfaces() {
        ImmutableConnectorInterface discoveryInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.DISCOVERY, "v2", List.of());
        return Stream
                .of(arguments(named("unrelated discovery interface", discoveryInterface)),
                        arguments(named("missing protocol version", cryptographyInterface(null))),
                        arguments(named("unsupported future protocol", cryptographyInterface("v3"))),
                        arguments(named("legacy protocol cannot use interface association",
                                cryptographyInterface("v1"))));
    }
}
