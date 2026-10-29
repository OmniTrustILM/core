package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.client.CryptographyV2ApiClients;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyOperationScope;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

/**
 * Selects the key-provider adapter from the token's persisted connector-interface association.
 */
@Component
public class KeyProviderAdapterFactory {

    private final ConnectorInternalService connectorInternalService;
    private final ConnectorApiFactory connectorApiFactory;
    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundSecretContainment;
    private final CryptographyV2ApiClients cryptographyV2ApiClients;
    private final ConnectorCapabilityService connectorCapabilityService;
    private final OperationResponseValidator responseValidator;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final KeyOperationCache keyOperationCache;

    public KeyProviderAdapterFactory(ConnectorInternalService connectorInternalService,
            ConnectorApiFactory connectorApiFactory, AttributeEngine attributeEngine,
            OperationAttributeResolver operationAttributeResolver, OutboundSecretContainment outboundSecretContainment,
            CryptographyV2ApiClients cryptographyV2ApiClients, ConnectorCapabilityService connectorCapabilityService,
            OperationResponseValidator responseValidator, CryptographicKeyRepository cryptographicKeyRepository,
            KeyOperationCache keyOperationCache) {
        this.connectorInternalService = connectorInternalService;
        this.connectorApiFactory = connectorApiFactory;
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundSecretContainment = outboundSecretContainment;
        this.cryptographyV2ApiClients = cryptographyV2ApiClients;
        this.connectorCapabilityService = connectorCapabilityService;
        this.responseValidator = responseValidator;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.keyOperationCache = keyOperationCache;
    }

    /** A missing interface association identifies a legacy token, even if its connector now advertises v2. */
    public KeyProviderAdapter forToken(TokenInstanceFullModel tokenInstance) throws NotFoundException {
        Objects.requireNonNull(tokenInstance, "A token instance is required to select a key-provider adapter.");

        if (tokenInstance.connectorUuid() == null) {
            throw new NotFoundException(Connector.class, tokenInstance.connectorName());
        }

        ImmutableConnectorFullModel connector = connectorInternalService
                .getConnectorFullModelForApiClient(tokenInstance.connectorUuid());
        ImmutableConnectorInterface iface = tokenInstance.connectorInterface();
        if (iface == null) {
            return new KeyProviderV1Adapter(connectorApiFactory, connector, attributeEngine);
        }
        return forInterface(iface.code(), iface.version(), connector,
                "token instance " + tokenInstance.toIdentifierString(), this::currentScope);
    }

    /** Operations take their scope from the token and profile the cached key item names. */
    public KeyProviderAdapter forKeyItem(CryptographicKeyItemOperationModel keyItem) throws NotFoundException {
        Objects.requireNonNull(keyItem, "A key item is required to select a key-provider adapter.");
        return adapterFor(keyItem, KeyProviderAdapterFactory::keyItemScope);
    }

    /**
     * Operations take their scope from the key's current row. The validator checks the row of a key inside a token
     * profile before each v2 operation resolves an attribute or calls the connector.
     */
    public KeyProviderAdapter forKeyItemInCurrentScope(CryptographicKeyItemOperationModel keyItem,
            Consumer<KeyOperationScope> scopeValidator) throws NotFoundException {
        Objects.requireNonNull(scopeValidator, "A scope validator is required.");
        Objects.requireNonNull(keyItem, "A key item is required to select a key-provider adapter.");
        return adapterFor(keyItem, item -> {
            KeyOperationScope scope = currentScope(item);
            scopeValidator.accept(scope);
            return scope;
        });
    }

    private KeyProviderAdapter adapterFor(CryptographicKeyItemOperationModel keyItem,
            KeyOperationScopeSource scopeSource) throws NotFoundException {
        if (keyItem.connectorUuid() == null) {
            throw new NotFoundException(Connector.class, keyItem.keyItemUuid());
        }
        // The cached single-row lookup: routing comes from the item's own interface columns, so the
        // connector's interfaces and function groups are not needed here.
        ApiClientConnectorInfo connector = connectorInternalService.getConnectorForApiClient(keyItem.connectorUuid());
        if (!keyItem.hasConnectorInterface()) {
            return new KeyProviderV1Adapter(connectorApiFactory, connector, attributeEngine);
        }
        return forInterface(keyItem.connectorInterfaceCode(), keyItem.connectorInterfaceVersion(), connector,
                "key item " + keyItem.toIdentifierString(), scopeSource);
    }

    /** A key moved to another profile keeps the cached item's scope until the key item cache drops the item. */
    private static KeyOperationScope keyItemScope(CryptographicKeyItemOperationModel keyItem) throws NotFoundException {
        KeyOperationScope scope = new KeyOperationScope(keyItem.tokenProfileUuid(),
                keyItem.tokenInstanceReferenceUuid());
        return requireInProfile(keyItem.keyUuid(), scope);
    }

    private KeyOperationScope currentScope(CryptographicKeyItemOperationModel keyItem) throws NotFoundException {
        KeyOperationScope scope = cryptographicKeyRepository
                .findOperationScopeByUuid(keyItem.keyUuid())
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, keyItem.keyUuid()));
        return requireInProfile(keyItem.keyUuid(), scope);
    }

    private static KeyOperationScope requireInProfile(UUID keyUuid, KeyOperationScope scope) throws NotFoundException {
        if (scope.tokenProfileUuid() == null || scope.tokenInstanceReferenceUuid() == null) {
            throw new NotFoundException("Key " + keyUuid + " is outside any token profile.");
        }
        return scope;
    }

    private KeyProviderAdapter forInterface(ConnectorInterface code, String version, ApiClientConnectorInfo connector,
            String owner, KeyOperationScopeSource scopeSource) {
        if (code != ConnectorInterface.CRYPTOGRAPHY) {
            throw new UnsupportedCryptographyProviderVersionException(
                    "Key provider is associated with a non-cryptography connector interface (" + owner + ")");
        }
        if (version == null) {
            throw new UnsupportedCryptographyProviderVersionException(
                    "Cryptography connector interface has no version (" + owner + ")");
        }
        if ("v2".equals(version)) {
            return new KeyProviderV2Adapter(cryptographyV2ApiClients, connector, attributeEngine,
                    operationAttributeResolver, outboundSecretContainment, connectorCapabilityService,
                    responseValidator, scopeSource, keyOperationCache);
        }
        throw new UnsupportedCryptographyProviderVersionException(
                "Unsupported cryptography connector interface version: " + version + " (" + owner + ")");
    }
}
