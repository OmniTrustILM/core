package com.otilm.core.service.handler.token;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v2.TokenSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/** Adapter for stateless cryptography-provider v2 connectors. */
public class TokenProviderV2Adapter implements TokenProviderAdapter {

    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundSecretContainment;
    private final ApiClientConnectorInfo connectorInfo;
    private final TokenSyncApiClient tokenApiClient;
    private final CryptographicOperationsSyncApiClient operationsApiClient;

    public TokenProviderV2Adapter(ConnectorApiFactory connectorApiFactory, AttributeEngine attributeEngine,
            OperationAttributeResolver operationAttributeResolver, OutboundSecretContainment outboundSecretContainment,
            ApiClientConnectorInfo connectorInfo, CryptographicOperationsSyncApiClient operationsApiClient) {
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundSecretContainment = outboundSecretContainment;
        this.connectorInfo = connectorInfo;
        this.tokenApiClient = connectorApiFactory.getTokenInstanceApiClientV2(connectorInfo);
        this.operationsApiClient = operationsApiClient;
    }

    @Override
    public List<BaseAttribute> listTokenAttributes(@Nullable String kind) throws ConnectorException {
        List<BaseAttribute> response = tokenApiClient.listTokenAttributes(connectorInfo);
        List<BaseAttribute> definitions = requireAttributeList(response, connectorInfo, "token attributes");
        persistAttributeDefinitions(UUID.fromString(connectorInfo.getUuid()), null, definitions, "token attributes");
        return definitions;
    }

    @Override
    public TokenInstanceStatusDetailDto getStatus(TokenInstanceBasicModel tokenInstance) throws ConnectorException {
        TokenStatusResponseV2Dto response = tokenApiClient
                .getTokenStatus(connectorInfo, tokenScopedRequest(tokenInstance));
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
    public List<BaseAttribute> listTokenProfileAttributes(TokenInstanceBasicModel tokenInstance)
            throws ConnectorException {
        TokenScopedRequestV2Dto request = tokenScopedRequest(tokenInstance);
        List<BaseAttribute> response = tokenApiClient.listTokenProfileAttributes(connectorInfo, request);
        List<BaseAttribute> definitions = requireAttributeList(response, connectorInfo, "token-profile attributes");
        persistAttributeDefinitions(tokenInstance.connectorUuid(), request, definitions, "token-profile attributes");
        return definitions;
    }

    @Override
    public List<KeyUsage> listSupportedKeyUsages(TokenInstanceBasicModel tokenInstance) throws ConnectorException {
        List<KeyUsage> response = tokenApiClient
                .listTokenProfileKeyUsages(connectorInfo, tokenScopedRequest(tokenInstance));
        if (response == null) {
            throw new ConnectorException("Connector returned no Key Usages", connectorInfo);
        }
        return response;
    }

    @Override
    public List<KeyRequestType> listSupportedKeyRequestTypes(TokenProfileBasicModel tokenProfile)
            throws ConnectorException {
        return tokenApiClient.listSupportedKeyRequestTypes(connectorInfo, tokenProfileScopedRequest(tokenProfile));
    }

    private TokenScopedRequestV2Dto tokenScopedRequest(TokenInstanceBasicModel tokenInstance)
            throws ConnectorException {
        List<RequestAttribute> storedAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN, tokenInstance.uuid())
                        .connector(tokenInstance.connectorUuid())
                        .build());
        TokenScopedRequestV2Dto request = new TokenScopedRequestV2Dto();
        request
                .setTokenAttributes(operationAttributeResolver
                        .resolveForConnectorRequestAsSystem(tokenInstance.connectorUuid(), storedAttributes));
        return request;
    }

    @Override
    public List<BaseAttribute> listRandomAttributes(TokenInstanceBasicModel tokenInstance,
            TokenProfileBasicModel tokenProfile) throws ConnectorException {
        TokenProfileScopedRequestV2Dto request = tokenProfileScopedRequest(tokenProfile);
        List<BaseAttribute> definitions = fetchRandomSchema(request);
        persistAttributeDefinitions(tokenInstance.connectorUuid(), request, definitions, "random-data attributes");
        return definitions;
    }

    @Override
    public RandomDataResponseDto randomData(TokenInstanceBasicModel tokenInstance, TokenProfileBasicModel tokenProfile,
            RandomDataRequestDto request) throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(tokenProfile);
        List<RequestAttribute> attributes = request.getAttributes() == null ? List.of() : request.getAttributes();
        List<BaseAttribute> definitions = fetchRandomSchema(scope);
        assertNoExpandedSecretEchoed(scope, definitions);
        AttributeDefinitionUtils.validateAttributes(definitions, attributes);
        RandomDataRequestV2Dto body = new RandomDataRequestV2Dto();
        body.setTokenAttributes(scope.getTokenAttributes());
        body.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        body.setKeyUsages(scope.getKeyUsages());
        body.setLength(request.getLength());
        body.setOperationAttributes(attributes);
        RandomDataResponseV2Dto connectorResponse = operationsApiClient.randomData(connectorInfo, body);
        if (connectorResponse == null || connectorResponse.getData() == null
                || connectorResponse.getData().length == 0) {
            throw new ConnectorException("Connector returned no random data", connectorInfo);
        }
        RandomDataResponseDto response = new RandomDataResponseDto();
        response.setData(Base64.getEncoder().encodeToString(connectorResponse.getData()));
        return response;
    }

    private List<BaseAttribute> fetchRandomSchema(TokenProfileScopedRequestV2Dto request) throws ConnectorException {
        return requireAttributeList(operationsApiClient.listRandomAttributes(connectorInfo, request), connectorInfo,
                "random-data attributes");
    }

    private TokenProfileScopedRequestV2Dto tokenProfileScopedRequest(TokenProfileBasicModel tokenProfile)
            throws ConnectorException {
        UUID connectorUuid = UUID.fromString(connectorInfo.getUuid());
        List<RequestAttribute> storedTokenAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN, tokenProfile.tokenInstanceReferenceUuid())
                        .connector(connectorUuid)
                        .build());

        List<RequestAttribute> resolvedTokenAttributes = operationAttributeResolver
                .resolveForConnectorRequestAsSystem(connectorUuid, storedTokenAttributes);

        List<RequestAttribute> storedProfileAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN_PROFILE, tokenProfile.uuid())
                        .connector(connectorUuid)
                        .build());
        List<RequestAttribute> resolvedTokenProfileAttributes = operationAttributeResolver
                .resolveForConnectorRequestAsSystem(connectorUuid, storedProfileAttributes);

        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(resolvedTokenAttributes);
        request.setTokenProfileAttributes(resolvedTokenProfileAttributes);
        request.setKeyUsages(Set.copyOf(tokenProfile.usages()));
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

    /**
     * Refuses a schema that echoes back a secret the matching request expanded for the connector.
     *
     * @param sentRequest the request whose resolved attributes went out, or null when the call sent none
     */
    private void assertNoExpandedSecretEchoed(@Nullable TokenScopedRequestV2Dto sentRequest,
            List<BaseAttribute> definitions) {
        Set<String> expandedSecrets = new HashSet<>();
        if (sentRequest != null) {
            outboundSecretContainment
                    .recordExpandedSecretsFromRequest(sentRequest.getTokenAttributes(), expandedSecrets);
            if (sentRequest instanceof TokenProfileScopedRequestV2Dto profileScoped) {
                outboundSecretContainment
                        .recordExpandedSecretsFromRequest(profileScoped.getTokenProfileAttributes(), expandedSecrets);
            }
        }
        outboundSecretContainment.assertNoExpandedSecretOutbound(definitions, expandedSecrets);
    }

    private void persistAttributeDefinitions(UUID connectorUuid, @Nullable TokenScopedRequestV2Dto sentRequest,
            List<BaseAttribute> definitions, String operation) throws ConnectorException {
        assertNoExpandedSecretEchoed(sentRequest, definitions);
        try {
            attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, definitions);
        } catch (AttributeException e) {
            throw new ConnectorException("Unable to persist " + operation + " returned by connector", e, connectorInfo);
        }
    }
}
