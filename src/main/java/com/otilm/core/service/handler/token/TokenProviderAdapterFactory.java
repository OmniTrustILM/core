package com.otilm.core.service.handler.token;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/** Selects the token-provider adapter from a connector's advertised protocol or a token's persisted association. */
@Component
public class TokenProviderAdapterFactory {

    private final ConnectorApiFactory connectorApiFactory;
    private final ConnectorInternalService connectorInternalService;
    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;

    public TokenProviderAdapterFactory(ConnectorApiFactory connectorApiFactory,
            ConnectorInternalService connectorInternalService, AttributeEngine attributeEngine,
            OperationAttributeResolver operationAttributeResolver) {
        this.connectorApiFactory = connectorApiFactory;
        this.connectorInternalService = connectorInternalService;
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
    }

    public TokenProviderAdapter forConnector(ImmutableConnectorFullModel connector) {
        return forConnectorWithBinding(connector).adapter();
    }

    /**
     * Selects the adapter for a connector and returns the exact connector-interface row a new token must persist.
     * Legacy v1 connectors deliberately have no interface association.
     */
    public TokenProviderBinding forConnectorWithBinding(ImmutableConnectorFullModel connector) {
        Objects.requireNonNull(connector, "A connector is required to select a token-provider adapter.");

        List<ImmutableConnectorInterface> cryptographyInterfaces = connector
                .connectorInterfaces()
                .stream()
                .filter(iface -> iface.code() == ConnectorInterface.CRYPTOGRAPHY)
                .sorted(Comparator
                        .comparing(ImmutableConnectorInterface::uuid, Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();

        ImmutableConnectorInterface v2Interface = cryptographyInterfaces
                .stream()
                .filter(iface -> "v2".equals(iface.version()))
                .findFirst()
                .orElse(null);
        if (v2Interface != null) {
            return new TokenProviderBinding(new TokenProviderV2Adapter(connectorApiFactory, attributeEngine,
                    operationAttributeResolver, connector), v2Interface);
        }
        if (!cryptographyInterfaces.isEmpty()) {
            String versions = cryptographyInterfaces
                    .stream()
                    .map(iface -> Objects.toString(iface.version(), "<missing>"))
                    .sorted()
                    .collect(Collectors.joining(", "));
            throw new UnsupportedCryptographyProviderVersionException(
                    "Unsupported cryptography connector interface version(s): " + versions + " (connector "
                            + connector.uuid() + ")");
        }
        if (hasLegacyCryptographyProvider(connector)) {
            return new TokenProviderBinding(new TokenProviderV1Adapter(connectorApiFactory, connector), null);
        }
        throw new UnsupportedCryptographyProviderVersionException(
                "Connector has no supported cryptography provider (connector " + connector.uuid() + ")");
    }

    /** Selects the adapter bound to an existing token. A missing interface association identifies a legacy token. */
    public TokenProviderAdapter forToken(TokenInstanceFullModel tokenInstance) throws NotFoundException {
        Objects.requireNonNull(tokenInstance, "A token instance is required to select a token-provider adapter.");

        if (tokenInstance.connectorUuid() == null) {
            throw new NotFoundException(Connector.class, tokenInstance.connectorName());
        }

        ImmutableConnectorFullModel connector = connectorInternalService
                .getConnectorFullModelForApiClient(tokenInstance.connectorUuid());
        ImmutableConnectorInterface iface = tokenInstance.connectorInterface();
        if (iface == null) {
            return new TokenProviderV1Adapter(connectorApiFactory, connector);
        }
        return forInterface(iface, connector, "token instance " + tokenInstance.uuid());
    }

    private TokenProviderAdapter forInterface(ImmutableConnectorInterface iface, ImmutableConnectorFullModel connector,
            String owner) {
        if (iface.code() != ConnectorInterface.CRYPTOGRAPHY) {
            throw new UnsupportedCryptographyProviderVersionException(
                    "Token provider is associated with a non-cryptography connector interface (" + owner + ")");
        }
        String version = iface.version();
        if (version == null) {
            throw new UnsupportedCryptographyProviderVersionException(
                    "Cryptography connector interface has no version (" + owner + ")");
        }
        if ("v2".equals(version)) {
            return new TokenProviderV2Adapter(connectorApiFactory, attributeEngine, operationAttributeResolver,
                    connector);
        }
        throw new UnsupportedCryptographyProviderVersionException(
                "Unsupported cryptography connector interface version: " + version + " (" + owner + ")");
    }

    private boolean hasLegacyCryptographyProvider(ImmutableConnectorFullModel connector) {
        return connector
                .functionGroups()
                .stream()
                .anyMatch(group -> group != null && group.code() == FunctionGroupCode.CRYPTOGRAPHY_PROVIDER);
    }
}
