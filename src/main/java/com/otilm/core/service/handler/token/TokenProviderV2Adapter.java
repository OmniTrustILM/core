package com.otilm.core.service.handler.token;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.TokenSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.token.TokenScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/** Adapter for stateless cryptography-provider v2 connectors. */
public class TokenProviderV2Adapter implements TokenProviderAdapter {

    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;
    private final ApiClientConnectorInfo connectorInfo;
    private final TokenSyncApiClient tokenApiClient;

    public TokenProviderV2Adapter(ConnectorApiFactory connectorApiFactory, AttributeEngine attributeEngine,
            OperationAttributeResolver operationAttributeResolver, ApiClientConnectorInfo connectorInfo) {
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.connectorInfo = connectorInfo;
        this.tokenApiClient = connectorApiFactory.getTokenInstanceApiClientV2(connectorInfo);
    }

    @Override
    public List<BaseAttribute> listTokenAttributes(@Nullable String kind) throws ConnectorException {
        List<BaseAttribute> response = tokenApiClient.listTokenAttributes(connectorInfo);
        List<BaseAttribute> definitions = requireAttributeList(response, connectorInfo, "token attributes");
        persistAttributeDefinitions(UUID.fromString(connectorInfo.getUuid()), definitions, connectorInfo,
                "token attributes");
        return definitions;
    }

    @Override
    public TokenInstanceStatusDetailDto getStatus(TokenInstanceBasicModel tokenInstanceReference)
            throws ConnectorException {
        TokenStatusResponseV2Dto response = tokenApiClient
                .getTokenStatus(connectorInfo, scopedRequest(tokenInstanceReference));
        if (response == null) {
            throw new ConnectorException("Connector returned no token status response", connectorInfo);
        }
        if (response.getStatus() == null) {
            throw new ConnectorException("Connector returned a token status response without status", connectorInfo);
        }
        TokenInstanceStatusDetailDto detail = new TokenInstanceStatusDetailDto();
        detail.setStatus(normalize(response.getStatus()));
        detail.setComponents(Map.of());
        return detail;
    }

    @Override
    public List<BaseAttribute> listTokenProfileAttributes(TokenInstanceBasicModel tokenInstanceReference)
            throws ConnectorException {
        List<BaseAttribute> response = tokenApiClient
                .listTokenProfileAttributes(connectorInfo, scopedRequest(tokenInstanceReference));
        List<BaseAttribute> definitions = requireAttributeList(response, connectorInfo, "token-profile attributes");
        persistAttributeDefinitions(tokenInstanceReference.connectorUuid(), definitions, connectorInfo,
                "token-profile attributes");
        return definitions;
    }

    @Override
    public List<KeyUsage> listSupportedKeyUsages(TokenInstanceBasicModel tokenInstanceReference)
            throws ConnectorException {
        List<KeyUsage> response = tokenApiClient
                .listTokenProfileKeyUsages(connectorInfo, scopedRequest(tokenInstanceReference));
        if (response == null) {
            throw new ConnectorException("Connector returned no Key Usages", connectorInfo);
        }
        return response;
    }

    private TokenScopedRequestV2Dto scopedRequest(TokenInstanceBasicModel tokenInstance) throws ConnectorException {
        List<RequestAttribute> storedAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN, tokenInstance.uuid())
                        .connector(tokenInstance.connectorUuid())
                        .build());
        List<RequestAttribute> resolvedAttributes = operationAttributeResolver
                .resolveForConnectorRequestAsSystem(tokenInstance.connectorUuid(), storedAttributes);
        TokenScopedRequestV2Dto request = new TokenScopedRequestV2Dto();
        request.setTokenAttributes(resolvedAttributes);
        return request;
    }

    private TokenInstanceStatus normalize(TokenStatusV2 status) {
        return switch (status) {
            case CONNECTED -> TokenInstanceStatus.CONNECTED;
            case DISCONNECTED -> TokenInstanceStatus.DISCONNECTED;
            case WARNING -> TokenInstanceStatus.WARNING;
            case UNKNOWN -> TokenInstanceStatus.UNKNOWN;
        };
    }

    private List<BaseAttribute> requireAttributeList(List<BaseAttribute> response, ApiClientConnectorInfo connectorInfo,
            String operation) throws ConnectorException {
        if (response == null) {
            throw new ConnectorException("Connector returned no " + operation + " response", connectorInfo);
        }
        return response;
    }

    private void persistAttributeDefinitions(UUID connectorUuid, List<BaseAttribute> definitions,
            ApiClientConnectorInfo connectorInfo, String operation) throws ConnectorException {
        try {
            attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, definitions);
        } catch (AttributeException e) {
            throw new ConnectorException("Unable to persist " + operation + " returned by connector", e, connectorInfo);
        }
    }
}
