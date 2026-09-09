package com.otilm.core.service.handler.token;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.AttributeSyncApiClient;
import com.otilm.api.interfaces.client.v1.TokenInstanceSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import java.util.Arrays;
import java.util.List;
import org.jspecify.annotations.Nullable;

/** Adapter for legacy cryptography-provider v1 connectors. */
public class TokenProviderV1Adapter
        implements
            TokenProviderAdapter,
            RemoteTokenLifecycleCapability,
            TokenActivationCapability,
            TokenProfileValidationCapability,
            TokenConfigurationValidationCapability {

    private final ApiClientConnectorInfo connectorInfo;
    private final TokenInstanceSyncApiClient tokenApiClient;
    private final AttributeSyncApiClient attributeApiClient;

    public TokenProviderV1Adapter(ConnectorApiFactory connectorApiFactory, ApiClientConnectorInfo connectorInfo) {
        this.connectorInfo = connectorInfo;
        this.tokenApiClient = connectorApiFactory.getTokenInstanceApiClient(connectorInfo);
        this.attributeApiClient = connectorApiFactory.getAttributeApiClient(connectorInfo);
    }

    @Override
    public List<BaseAttribute> listTokenAttributes(@Nullable String kind) throws ConnectorException {
        return attributeApiClient
                .listAttributeDefinitions(connectorInfo, FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, kind);
    }

    @Override
    public TokenInstanceStatusDetailDto getStatus(TokenInstanceBasicModel tokenInstanceReference)
            throws ConnectorException {
        TokenInstanceStatusDto response = tokenApiClient
                .getTokenInstanceStatus(connectorInfo, tokenInstanceReference.tokenInstanceUuid());
        if (response == null) {
            throw new ConnectorException("Connector returned no token status response", connectorInfo);
        }
        if (response.getStatus() == null) {
            throw new ConnectorException("Connector returned a token status response without status", connectorInfo);
        }
        TokenInstanceStatusDetailDto detail = new TokenInstanceStatusDetailDto();
        detail.setStatus(response.getStatus());
        detail.setComponents(response.getComponents());
        return detail;
    }

    @Override
    public List<BaseAttribute> listTokenProfileAttributes(TokenInstanceBasicModel tokenInstanceReference)
            throws ConnectorException {
        return tokenApiClient.listTokenProfileAttributes(connectorInfo, tokenInstanceReference.tokenInstanceUuid());
    }

    @Override
    public List<KeyUsage> listSupportedKeyUsages(TokenInstanceBasicModel tokenInstanceReference) {
        // The v1 connector protocol has no operation for discovering supported key usages.
        return Arrays.stream(KeyUsage.values()).toList();
    }

    @Override
    public TokenInstanceDto createRemoteToken(TokenInstanceRequestDto request) throws ConnectorException {
        TokenInstanceDto response = tokenApiClient.createTokenInstance(connectorInfo, request);
        if (response == null) {
            throw new ConnectorException("Connector returned no token instance response", connectorInfo);
        }
        return response;
    }

    @Override
    public TokenInstanceDto updateRemoteToken(TokenInstanceBasicModel tokenInstance, TokenInstanceRequestDto request)
            throws ConnectorException {
        TokenInstanceDto response = tokenApiClient
                .updateTokenInstance(connectorInfo, tokenInstance.tokenInstanceUuid(), request);
        if (response == null) {
            throw new ConnectorException("Connector returned no token instance response", connectorInfo);
        }
        return response;
    }

    @Override
    public void removeRemoteToken(TokenInstanceBasicModel tokenInstance) throws ConnectorException {
        tokenApiClient.removeTokenInstance(connectorInfo, tokenInstance.tokenInstanceUuid());
    }

    @Override
    public List<BaseAttribute> listActivationAttributes(TokenInstanceBasicModel tokenInstance)
            throws ConnectorException {
        return tokenApiClient.listTokenInstanceActivationAttributes(connectorInfo, tokenInstance.tokenInstanceUuid());
    }

    @Override
    public void activate(TokenInstanceBasicModel tokenInstance, List<RequestAttribute> attributes)
            throws ConnectorException {
        tokenApiClient.activateTokenInstance(connectorInfo, tokenInstance.tokenInstanceUuid(), attributes);
    }

    @Override
    public void deactivate(TokenInstanceBasicModel tokenInstance) throws ConnectorException {
        tokenApiClient.deactivateTokenInstance(connectorInfo, tokenInstance.tokenInstanceUuid());
    }

    @Override
    public void validateTokenProfileAttributes(TokenInstanceBasicModel tokenInstance, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        tokenApiClient.validateTokenProfileAttributes(connectorInfo, tokenInstance.tokenInstanceUuid(), attributes);
    }

    @Override
    public void validateTokenAttributes(@Nullable String kind, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        attributeApiClient.validateAttributes(connectorInfo, FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, attributes, kind);
    }

}
