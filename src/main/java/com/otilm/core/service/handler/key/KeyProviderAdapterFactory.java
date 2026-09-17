package com.otilm.core.service.handler.key;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.Objects;
import org.springframework.stereotype.Component;

/** Selects the key-provider adapter from the token's persisted connector-interface association. */
@Component
public class KeyProviderAdapterFactory {

    private final ConnectorInternalService connectorInternalService;
    private final ConnectorApiFactory connectorApiFactory;
    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundSecretContainment;

    public KeyProviderAdapterFactory(ConnectorInternalService connectorInternalService,
            ConnectorApiFactory connectorApiFactory, AttributeEngine attributeEngine,
            OperationAttributeResolver operationAttributeResolver,
            OutboundSecretContainment outboundSecretContainment) {
        this.connectorInternalService = connectorInternalService;
        this.connectorApiFactory = connectorApiFactory;
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundSecretContainment = outboundSecretContainment;
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
        return forInterface(iface, connector, "token instance " + tokenInstance.toIdentifierString());
    }

    private KeyProviderAdapter forInterface(ImmutableConnectorInterface iface, ImmutableConnectorFullModel connector,
            String owner) {
        if (iface.code() != ConnectorInterface.CRYPTOGRAPHY) {
            throw new UnsupportedCryptographyProviderVersionException(
                    "Key provider is associated with a non-cryptography connector interface (" + owner + ")");
        }
        String version = iface.version();
        if (version == null) {
            throw new UnsupportedCryptographyProviderVersionException(
                    "Cryptography connector interface has no version (" + owner + ")");
        }
        if ("v2".equals(version)) {
            return new KeyProviderV2Adapter(connectorApiFactory, connector, attributeEngine, operationAttributeResolver,
                    outboundSecretContainment);
        }
        throw new UnsupportedCryptographyProviderVersionException(
                "Unsupported cryptography connector interface version: " + version + " (" + owner + ")");
    }
}
