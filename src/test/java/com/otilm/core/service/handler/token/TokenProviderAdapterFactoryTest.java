package com.otilm.core.service.handler.token;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.model.connector.ConnectorFunctionGroupModel;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Pins the factory's routing table, including each refusal branch. */
class TokenProviderAdapterFactoryTest {

    private TokenProviderAdapterFactory factory;
    private ConnectorInternalService connectorInternalService;

    @BeforeEach
    void setUp() {
        connectorInternalService = mock(ConnectorInternalService.class);
        factory = new TokenProviderAdapterFactory(mock(ConnectorApiFactory.class), connectorInternalService,
                mock(AttributeEngine.class), mock(OperationAttributeResolver.class));
    }

    @Test
    void forConnector_returnsV1Adapter_forLegacyProvider() {
        // given
        var legacyProvider = new ConnectorFunctionGroupModel(UUID.randomUUID(), "provider",
                FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, List.of());
        ImmutableConnectorFullModel connector = connector(List.of(), List.of(legacyProvider));

        // when
        TokenProviderAdapter adapter = factory.forConnector(connector);

        // then
        assertInstanceOf(TokenProviderV1Adapter.class, adapter);
    }

    @Test
    void forConnector_returnsV2Adapter_forCryptographyV2Interface() {
        // given
        ImmutableConnectorFullModel connector = connector(List.of(cryptographyInterface("v2")), List.of());

        // when
        TokenProviderAdapter adapter = factory.forConnector(connector);

        // then
        assertInstanceOf(TokenProviderV2Adapter.class, adapter);
    }

    @Test
    void forConnector_throws_forUnsupportedInterfaceVersion() {
        // given
        ImmutableConnectorFullModel connector = connector(List.of(cryptographyInterface("v3")), List.of());

        // when
        Executable selectAdapter = () -> factory.forConnector(connector);

        // then
        assertThrows(UnsupportedCryptographyProviderVersionException.class, selectAdapter);
    }

    @Test
    void forToken_throws_forInterfaceWithoutVersion() throws Exception {
        // given
        ImmutableConnectorInterface interfaceWithoutVersion = cryptographyInterface(null);
        ImmutableTokenInstanceFullModel token = tokenWithInterface(interfaceWithoutVersion);

        // when
        ThrowingCallable selectAdapter = () -> factory.forToken(token);

        // then
        assertThatThrownBy(selectAdapter)
                .isInstanceOf(UnsupportedCryptographyProviderVersionException.class)
                .hasMessageContaining("has no version");
    }

    @Test
    void forToken_throws_forNonCryptographyInterface() throws Exception {
        // given
        ImmutableConnectorInterface nonCryptographyInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.DISCOVERY, "v2", List.of());
        ImmutableTokenInstanceFullModel token = tokenWithInterface(nonCryptographyInterface);

        // when
        ThrowingCallable selectAdapter = () -> factory.forToken(token);

        // then
        assertThatThrownBy(selectAdapter)
                .isInstanceOf(UnsupportedCryptographyProviderVersionException.class)
                .hasMessageContaining("non-cryptography");
    }

    @Test
    void forConnectorWithBinding_throws_withoutSupportedProvider() {
        // given
        ImmutableConnectorFullModel connector = connector(List.of(), List.of());

        // when
        ThrowingCallable selectAdapter = () -> factory.forConnectorWithBinding(connector);

        // then
        assertThatThrownBy(selectAdapter)
                .isInstanceOf(UnsupportedCryptographyProviderVersionException.class)
                .hasMessageContaining("no supported cryptography provider");
    }

    @Test
    void forToken_throwsNotFound_forMissingConnector() {
        // given
        String missingConnectorName = "missing-connector";
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token",
                TokenInstanceStatus.UNKNOWN, "SOFT", null, missingConnectorName, null, null, Set.of());

        // when
        ThrowingCallable selectAdapter = () -> factory.forToken(token);

        // then
        assertThatThrownBy(selectAdapter)
                .isInstanceOf(com.otilm.api.exception.NotFoundException.class)
                .hasMessageContaining(missingConnectorName);
    }

    @Test
    void forToken_returnsV2Adapter_forPersistedCryptographyInterface() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorFullModel connector = connector(List.of(cryptographyInterface("v2")), List.of());
        when(connectorInternalService.getConnectorFullModelForApiClient(connectorUuid)).thenReturn(connector);
        var token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.UNKNOWN,
                "SOFT", connectorUuid, "connector", connector.connectorInterfaces().get(0).uuid(),
                connector.connectorInterfaces().get(0), Set.of());

        // when
        TokenProviderAdapter adapter = factory.forToken(token);

        // then
        assertInstanceOf(TokenProviderV2Adapter.class, adapter);
    }

    @Test
    void forToken_selectsLegacyAdapter_whenConnectorAdvertisesV2() throws Exception {
        // given
        ImmutableConnectorFullModel connector = connector(List.of(cryptographyInterface("v2")), List.of());
        when(connectorInternalService.getConnectorFullModelForApiClient(connector.uuid())).thenReturn(connector);
        var legacyToken = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), UUID.randomUUID().toString(),
                "legacy token", TokenInstanceStatus.ACTIVATED, null, connector.uuid(), connector.name(), null, null,
                Set.of());

        // when
        TokenProviderAdapter adapter = factory.forToken(legacyToken);

        // then
        assertInstanceOf(TokenProviderV1Adapter.class, adapter);
    }

    private ImmutableConnectorFullModel connector(List<ImmutableConnectorInterface> interfaces,
            List<ConnectorFunctionGroupModel> functionGroups) {
        return new ImmutableConnectorFullModel(UUID.randomUUID(), "connector", ConnectorVersion.V2, "http://localhost",
                null, List.of(), null, null, interfaces, functionGroups);
    }

    private ImmutableConnectorInterface cryptographyInterface(String version) {
        return new ImmutableConnectorInterface(UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, version, List.of());
    }

    private ImmutableTokenInstanceFullModel tokenWithInterface(ImmutableConnectorInterface connectorInterface)
            throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorFullModel connector = connector(List.of(connectorInterface), List.of());
        when(connectorInternalService.getConnectorFullModelForApiClient(connectorUuid)).thenReturn(connector);
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.UNKNOWN,
                "SOFT", connectorUuid, "connector", connectorInterface.uuid(), connectorInterface, Set.of());
    }
}
