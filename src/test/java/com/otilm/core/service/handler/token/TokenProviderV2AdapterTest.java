package com.otilm.core.service.handler.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v2.TokenSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class TokenProviderV2AdapterTest {

    private TokenSyncApiClient tokenApiClient;
    private CryptographicOperationsSyncApiClient operationsClient;
    private TokenProviderV2Adapter adapter;
    private ImmutableTokenInstanceBasicModel token;
    private AttributeEngine attributeEngine;
    private OperationAttributeResolver operationAttributeResolver;

    @BeforeEach
    void setUp() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorFullModel connector = connector(connectorUuid);
        ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
        attributeEngine = mock(AttributeEngine.class);
        operationAttributeResolver = mock(OperationAttributeResolver.class);
        tokenApiClient = mock(TokenSyncApiClient.class);
        operationsClient = mock(CryptographicOperationsSyncApiClient.class);
        when(connectorApiFactory.getTokenInstanceApiClientV2(connector)).thenReturn(tokenApiClient);
        when(attributeEngine.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of()))
                .thenReturn(List.of());
        adapter = new TokenProviderV2Adapter(connectorApiFactory, attributeEngine, operationAttributeResolver,
                new OutboundSecretContainment(new ObjectMapper()), connector, operationsClient);
        token = token(connectorUuid);
    }

    @Test
    void listSupportedKeyUsages_returnsConnectorCapabilities() throws Exception {
        List<KeyUsage> supported = List.of(KeyUsage.SIGN, KeyUsage.ENCRYPT);
        when(tokenApiClient.listTokenProfileKeyUsages(any(), any())).thenReturn(supported);

        assertSame(supported, adapter.listSupportedKeyUsages(token));
        verify(tokenApiClient).listTokenProfileKeyUsages(any(), any());
    }

    @Test
    void listSupportedKeyUsages_throwsConnectorException_forNullResponse() throws Exception {
        // given
        when(tokenApiClient.listTokenProfileKeyUsages(any(), any())).thenReturn(null);

        // when
        Executable listUsages = () -> adapter.listSupportedKeyUsages(token);

        // then
        ConnectorException exception = assertThrows(ConnectorException.class, listUsages);
        assertTrue(exception.getMessage().contains("Connector returned no Key Usages"));
    }

    @Test
    void listSupportedKeyRequestTypes_resolvesTokenAndProfileContext() throws Exception {
        // given
        var profile = profile();
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")), resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        List<KeyRequestType> supportedTypes = List.of(KeyRequestType.KEY_PAIR);
        when(tokenApiClient.listSupportedKeyRequestTypes(any(), any())).thenReturn(supportedTypes);

        // when
        List<KeyRequestType> types = adapter.listSupportedKeyRequestTypes(profile);

        // then
        assertEquals(supportedTypes, types);
        ArgumentCaptor<TokenProfileScopedRequestV2Dto> request = ArgumentCaptor
                .forClass(TokenProfileScopedRequestV2Dto.class);
        verify(tokenApiClient).listSupportedKeyRequestTypes(any(), request.capture());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
        assertFalse(new ObjectMapper().valueToTree(request.getValue()).has("keyUsages"));
    }

    @Test
    void listSupportedKeyRequestTypes_stopsWhenResolutionFails() throws Exception {
        // given
        var profile = profile();
        List<RequestAttribute> storedProfile = List.of(requestAttribute("unresolvable-profile"));
        ObjectAttributeContentInfo profileScope = ObjectAttributeContentInfo
                .builder(Resource.TOKEN_PROFILE, profile.uuid())
                .connector(token.connectorUuid())
                .build();
        when(attributeEngine.getRequestObjectDataAttributesContent(profileScope)).thenReturn(storedProfile);
        ConnectorException failure = new ConnectorException("Stored profile credential cannot be resolved");
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(token.connectorUuid(), storedProfile))
                .thenThrow(failure);

        // when
        Executable listTypes = () -> adapter.listSupportedKeyRequestTypes(profile);

        // then
        assertSame(failure, assertThrows(ConnectorException.class, listTypes));
        verifyNoInteractions(tokenApiClient);
    }

    @Test
    void listRandomAttributes_sendsTokenProfileScopeAndPersistsDefinitions() throws Exception {
        // given
        var profile = profile();
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")), resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        List<BaseAttribute> definitions = List.of(new DataAttributeV2());
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(definitions);

        // when
        List<BaseAttribute> result = adapter.listRandomAttributes(token, profile);

        // then
        assertSame(definitions, result);
        ArgumentCaptor<TokenProfileScopedRequestV2Dto> request = ArgumentCaptor
                .forClass(TokenProfileScopedRequestV2Dto.class);
        verify(operationsClient).listRandomAttributes(any(), request.capture());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
        assertFalse(new ObjectMapper().valueToTree(request.getValue()).has("keyUsages"));
        verify(attributeEngine).updateDataAttributeDefinitions(token.connectorUuid(), null, definitions);
    }

    @Test
    void randomData_validatesAttributesAgainstSchema_thenForwardsScopeLengthAndEncodesData() throws Exception {
        // given
        var profile = profile();
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")), resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        when(operationsClient.listRandomAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("length-hint", true)));
        RandomDataResponseV2Dto connectorResponse = new RandomDataResponseV2Dto();
        connectorResponse.setData(new byte[]{9, 8});
        when(operationsClient.randomData(any(), any())).thenReturn(connectorResponse);
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(2);
        request.setAttributes(List.of(stringAttribute("length-hint", "even")));

        // when
        RandomDataResponseDto response = adapter.randomData(token, profile, request);

        // then
        ArgumentCaptor<RandomDataRequestV2Dto> sent = ArgumentCaptor.forClass(RandomDataRequestV2Dto.class);
        verify(operationsClient).randomData(any(), sent.capture());
        assertEquals(resolvedToken, sent.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, sent.getValue().getTokenProfileAttributes());
        assertFalse(new ObjectMapper().valueToTree(sent.getValue()).has("keyUsages"));
        assertEquals(2, sent.getValue().getLength());
        assertSame(request.getAttributes(), sent.getValue().getOperationAttributes());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{9, 8}), response.getData());
    }

    @Test
    void randomData_resolvesTokenProfileScopeOnce_andNeverTouchesTheAttributeEngineForTheSchema() throws Exception {
        // given
        var profile = profile();
        when(operationsClient.listRandomAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("length-hint", false)));
        RandomDataResponseV2Dto connectorResponse = new RandomDataResponseV2Dto();
        connectorResponse.setData(new byte[]{1});
        when(operationsClient.randomData(any(), any())).thenReturn(connectorResponse);
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(1);
        request.setAttributes(List.of());

        // when
        adapter.randomData(token, profile, request);

        // then
        verify(attributeEngine).getRequestObjectDataAttributesContent(tokenScope());
        verify(attributeEngine)
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN_PROFILE, profile.uuid())
                        .connector(token.connectorUuid())
                        .build());
        verify(attributeEngine, never()).updateDataAttributeDefinitions(any(), any(), any());
        verify(attributeEngine, never()).validateUpdateDataAttributes(any(), any(), any(), any());
        verifyNoMoreInteractions(attributeEngine);
    }

    @Test
    void listRandomAttributes_rejectsSchemaEchoingAnExpandedSecret() throws Exception {
        // given
        var profile = profile();
        String expandedSecret = "resolved-token-password";
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")),
                List.of(secretAttribute(expandedSecret)));
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(), List.of());
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(definitionsWithDefault(expandedSecret));

        // when
        Executable listDefinitions = () -> adapter.listRandomAttributes(token, profile);

        // then
        assertThrows(OutboundSecretLeakException.class, listDefinitions);
        verify(attributeEngine, never()).updateDataAttributeDefinitions(any(), any(), any());
    }

    @Test
    void randomData_rejectsSchemaEchoingAnExpandedSecret_beforeCallingConnector() throws Exception {
        // given
        var profile = profile();
        String expandedSecret = "resolved-token-password";
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")),
                List.of(secretAttribute(expandedSecret)));
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(), List.of());
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(definitionsWithDefault(expandedSecret));
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(2);
        request.setAttributes(List.of());

        // when
        Executable generate = () -> adapter.randomData(token, profile, request);

        // then
        assertThrows(OutboundSecretLeakException.class, generate);
        verify(operationsClient, never()).randomData(any(), any());
    }

    @Test
    void randomData_rejectsResponseWithoutData() throws Exception {
        // given
        var profile = profile();
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(List.of());
        when(operationsClient.randomData(any(), any())).thenReturn(new RandomDataResponseV2Dto());
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(2);
        request.setAttributes(List.of());

        // when
        Executable generate = () -> adapter.randomData(token, profile, request);

        // then
        assertThrows(ConnectorException.class, generate);
    }

    @Test
    void randomData_rejectsInvalidAttributes_beforeCallingConnector() throws Exception {
        // given
        var profile = profile();
        when(operationsClient.listRandomAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("length-hint", true)));
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(2);
        request.setAttributes(List.of());

        // when
        Executable generate = () -> adapter.randomData(token, profile, request);

        // then
        assertThrows(ValidationException.class, generate);
        verify(operationsClient, never()).randomData(any(), any());
    }

    private ImmutableTokenProfileBasicModel profile() {
        return new ImmutableTokenProfileBasicModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
    }

    private void stubAttributes(Resource resource, UUID uuid, List<RequestAttribute> stored,
            List<RequestAttribute> resolved) throws ConnectorException {
        ObjectAttributeContentInfo scope = ObjectAttributeContentInfo
                .builder(resource, uuid)
                .connector(token.connectorUuid())
                .build();
        when(attributeEngine.getRequestObjectDataAttributesContent(scope)).thenReturn(stored);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(token.connectorUuid(), stored))
                .thenReturn(resolved);
    }

    private ObjectAttributeContentInfo tokenScope() {
        return ObjectAttributeContentInfo
                .builder(Resource.TOKEN, token.uuid())
                .connector(token.connectorUuid())
                .build();
    }

    private static DataAttributeV2 dataAttributeDefinition(String name, boolean required) {
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        properties.setRequired(required);
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName(name);
        definition.setContentType(AttributeContentType.STRING);
        definition.setProperties(properties);
        return definition;
    }

    private static RequestAttribute stringAttribute(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }

    private static RequestAttribute requestAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        return attribute;
    }

    private static RequestAttribute secretAttribute(String secret) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName("credential");
        attribute
                .setContent(List
                        .of(new SecretAttributeContentV2("credential-reference",
                                new SecretAttributeContentData(secret))));
        return attribute;
    }

    private static List<BaseAttribute> definitionsWithDefault(String value) {
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setName("length-hint");
        definition.setContent(List.of(new StringAttributeContentV2(value)));
        return List.of(definition);
    }

    private static ImmutableConnectorFullModel connector(UUID connectorUuid) {
        return new ImmutableConnectorFullModel(connectorUuid, "connector", ConnectorVersion.V2, "http://connector.test",
                null, List.of(), ConnectorStatus.CONNECTED, null, List.of(), List.of());
    }

    private static ImmutableTokenInstanceBasicModel token(UUID connectorUuid) {
        return new ImmutableTokenInstanceBasicModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.UNKNOWN,
                "SOFT", connectorUuid, "connector", UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2", 0);
    }
}
