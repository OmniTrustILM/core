package com.otilm.core.service.handler.key;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.client.CryptographyV2ApiClients;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.KeyOperationScope;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyProviderAdapterFactoryTest {

    private ConnectorInternalService connectorService;
    private ConnectorApiFactory clients;
    private CryptographyV2ApiClients v2Clients;
    private final CryptographicKeyRepository keyRepository = mock(CryptographicKeyRepository.class);
    private final AttributeEngine attributeEngine = mock(AttributeEngine.class);
    private KeyProviderAdapterFactory factory;
    private ImmutableConnectorFullModel connector;

    @BeforeEach
    void wireFactory() throws Exception {
        connectorService = mock(ConnectorInternalService.class);
        clients = mock(ConnectorApiFactory.class);
        v2Clients = mock(CryptographyV2ApiClients.class);
        factory = new KeyProviderAdapterFactory(connectorService, clients, attributeEngine,
                mock(OperationAttributeResolver.class), mock(OutboundSecretContainment.class), v2Clients,
                new ConnectorCapabilityService(), mock(OperationResponseValidator.class), keyRepository,
                KeyOperationCacheFixtures.keyOperationCache(attributeEngine));
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
        verify(v2Clients).getKeyManagementApiClient(connector);
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

    // ── ForKeyItem ────────────────────────────────────────────────────────────

    @Nested
    class ForKeyItem {

        @Test
        void selectsV1_forItemWithoutInterface() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(null, null);

            // when
            KeyProviderAdapter adapter = factory.forKeyItem(item);

            // then
            assertThat(adapter).isInstanceOf(KeyProviderV1Adapter.class);
            verify(clients).getKeyManagementApiClient(connector);
        }

        @Test
        void selectsV2_forCryptographyV2Interface() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");

            // when
            KeyProviderAdapter adapter = factory.forKeyItem(item);

            // then
            assertThat(adapter).isInstanceOf(KeyProviderV2Adapter.class);
            verify(v2Clients).getKeyManagementApiClient(connector);
        }

        @Test
        void scopesTheOperationByTheKeyItem_withoutReadingTheKey() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");
            CryptographicOperationsSyncApiClient operations = mock(CryptographicOperationsSyncApiClient.class);
            when(v2Clients.getCryptographicOperationsApiClient(connector)).thenReturn(operations);
            when(operations.listSignAttributes(any(), any())).thenReturn(List.of());
            KeyProviderAdapter adapter = factory.forKeyItem(item);

            // when
            adapter.listSignAttributes(item);

            // then
            verify(attributeEngine)
                    .getStoredObjectDataAttributesContent(
                            attributeScope(Resource.TOKEN, item.tokenInstanceReferenceUuid()));
            verify(attributeEngine)
                    .getStoredObjectDataAttributesContent(
                            attributeScope(Resource.TOKEN_PROFILE, item.tokenProfileUuid()));
            verifyNoInteractions(keyRepository);
        }

        @Test
        void rejectsAKeyItemOutsideAnyProfile_withoutReadingTheKey() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2", null);
            KeyProviderAdapter adapter = factory.forKeyItem(item);

            // when
            ThrowingCallable list = () -> adapter.listSignAttributes(item);

            // then
            assertThatThrownBy(list)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining("Key " + item.keyUuid() + " is outside any token profile.");
            verifyNoInteractions(keyRepository, attributeEngine);
        }

        @ParameterizedTest(name = "{0} {1}")
        @CsvSource(value = {"DISCOVERY,v2", "CRYPTOGRAPHY,", "CRYPTOGRAPHY,v3", "CRYPTOGRAPHY,v1"})
        void rejectsUnsupportedInterface(ConnectorInterface code, String version) {
            // given
            CryptographicKeyItemOperationModel item = keyItem(code, version);

            // when
            ThrowingCallable select = () -> factory.forKeyItem(item);

            // then
            assertThatThrownBy(select).isInstanceOf(UnsupportedCryptographyProviderVersionException.class);
            verifyNoInteractions(clients);
        }
    }

    // ── ForKeyItemInCurrentScope ──────────────────────────────────────────────

    @Nested
    class ForKeyItemInCurrentScope {

        @Test
        void appliesServiceScopeValidation_beforeBuildingTheRequest() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");
            KeyOperationScope scope = new KeyOperationScope(UUID.randomUUID(), UUID.randomUUID());
            when(keyRepository.findOperationScopeByUuid(item.keyUuid())).thenReturn(Optional.of(scope));
            ValidationException rejectedScope = new ValidationException(
                    "The key no longer belongs to the authorized profile.");
            KeyProviderAdapter adapter = factory.forKeyItemInCurrentScope(item, resolvedScope -> {
                assertThat(resolvedScope).isSameAs(scope);
                throw rejectedScope;
            });

            // when
            ThrowingCallable list = () -> adapter.listSignAttributes(item);

            // then
            assertThatThrownBy(list).isSameAs(rejectedScope);
            verify(keyRepository).findOperationScopeByUuid(item.keyUuid());
        }

        @Test
        void rejectsAKeyOutsideAnyProfile_beforeTheValidator() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");
            KeyOperationScope profileless = new KeyOperationScope(null, item.tokenInstanceReferenceUuid());
            when(keyRepository.findOperationScopeByUuid(item.keyUuid())).thenReturn(Optional.of(profileless));
            List<KeyOperationScope> validated = new ArrayList<>();
            KeyProviderAdapter adapter = factory.forKeyItemInCurrentScope(item, validated::add);

            // when
            ThrowingCallable list = () -> adapter.listSignAttributes(item);

            // then
            assertThatThrownBy(list)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining("Key " + item.keyUuid() + " is outside any token profile.");
            assertThat(validated).isEmpty();
        }
    }

    // ── ForKeyItemInUnchangedScope ────────────────────────────────────────────

    @Nested
    class ForKeyItemInUnchangedScope {

        @ParameterizedTest(name = "{0}")
        @MethodSource("movedScopes")
        void rejectsAKeyMovedOffTheCachedItemsScope(UnaryOperator<KeyOperationScope> move) throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");
            KeyOperationScope movedScope = move.apply(cachedScopeOf(item));
            when(keyRepository.findOperationScopeByUuid(item.keyUuid())).thenReturn(Optional.of(movedScope));
            KeyProviderAdapter adapter = factory.forKeyItemInUnchangedScope(item);

            // when
            ThrowingCallable list = () -> adapter.listEncryptAttributes(item);

            // then
            assertThatThrownBy(list)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Key token or token profile association changed during the operation.");
            verifyNoInteractions(attributeEngine);
        }

        @Test
        void scopesTheOperationByTheKeysRow_whenItMatchesTheCachedItem() throws Exception {
            // given
            CryptographicKeyItemOperationModel item = keyItem(ConnectorInterface.CRYPTOGRAPHY, "v2");
            when(keyRepository.findOperationScopeByUuid(item.keyUuid())).thenReturn(Optional.of(cachedScopeOf(item)));
            CryptographicOperationsSyncApiClient operations = mock(CryptographicOperationsSyncApiClient.class);
            when(v2Clients.getCryptographicOperationsApiClient(connector)).thenReturn(operations);
            when(operations.listEncryptAttributes(any(), any())).thenReturn(List.of());
            KeyProviderAdapter adapter = factory.forKeyItemInUnchangedScope(item);

            // when
            adapter.listEncryptAttributes(item);

            // then
            verify(keyRepository).findOperationScopeByUuid(item.keyUuid());
            verify(operations).listEncryptAttributes(any(), any());
        }

        private static Stream<Arguments> movedScopes() {
            return Stream
                    .of(arguments(named("moved to another token",
                            (UnaryOperator<KeyOperationScope>) scope -> new KeyOperationScope(scope.tokenProfileUuid(),
                                    UUID.randomUUID()))),
                            arguments(named("moved to another token profile",
                                    (UnaryOperator<KeyOperationScope>) scope -> new KeyOperationScope(UUID.randomUUID(),
                                            scope.tokenInstanceReferenceUuid()))));
        }

        private static KeyOperationScope cachedScopeOf(CryptographicKeyItemOperationModel item) {
            return new KeyOperationScope(item.tokenProfileUuid(), item.tokenInstanceReferenceUuid());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CryptographicKeyItemOperationModel keyItem(ConnectorInterface code, String version) {
        return keyItem(code, version, UUID.randomUUID());
    }

    private CryptographicKeyItemOperationModel keyItem(ConnectorInterface code, String version, UUID tokenProfileUuid) {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.SIGN), null,
                new RemoteKeyReference.MetadataReference(List.of(keyHandle())), connector.uuid(), UUID.randomUUID(),
                UUID.randomUUID(), code, version, UUID.randomUUID(), tokenProfileUuid);
    }

    private static MetadataAttributeV2 keyHandle() {
        MetadataAttributeV2 handle = new MetadataAttributeV2();
        handle.setName("key-handle");
        return handle;
    }

    private ObjectAttributeContentInfo attributeScope(Resource resource, UUID uuid) {
        return ObjectAttributeContentInfo.builder(resource, uuid).connector(connector.uuid()).build();
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
