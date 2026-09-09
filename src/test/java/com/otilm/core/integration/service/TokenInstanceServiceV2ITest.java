package com.otilm.core.integration.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenInstanceInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.DataAttributeV3Builder;
import com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@Transactional
@Rollback
class TokenInstanceServiceV2ITest extends BaseSpringBootTest {

    @Autowired
    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    private TokenInstanceInternalService tokenInstanceInternalService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @PersistenceContext
    private EntityManager entityManager;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private Connector connector;
    private ConnectorInterfaceEntity connectorInterface;

    @BeforeEach
    void setUp() {
        connectorMock = connectorMockFactory.startCryptographyProviderV2().stubTokenOperations();
        connector = persistV2Connector(connectorMock.getUrl());
        connectorInterface = persistCryptographyInterface(connector);
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void listTokenAttributes_ignoresLegacyKind_forV2Connector() throws Exception {
        // given
        String legacyKind = "SOFT";

        // when
        List<BaseAttribute> attributes = tokenInstanceService
                .listTokenAttributes(SecuredUUID.fromUUID(connector.getUuid()), legacyKind);

        // then
        assertNotNull(attributes);
        connectorMock.verifyTokenAttributesRequest();
    }

    @Test
    void getTokenInstance_refreshesAndPersistsV2Status() throws Exception {
        // given
        TokenInstanceReference token = persistToken("status-refresh-v2-token");

        // when
        TokenInstanceDetailDto detail = tokenInstanceService.getTokenInstance(SecuredUUID.fromUUID(token.getUuid()));

        // then
        assertEquals(TokenInstanceStatus.CONNECTED, detail.getStatus().getStatus());
        flushAndClear();
        TokenInstanceReference reloaded = tokenInstanceReferenceRepository.findById(token.getUuid()).orElseThrow();
        assertEquals(TokenInstanceStatus.CONNECTED, reloaded.getStatus());
    }

    @Test
    void createTokenInstance_persistsSelectedV2Interface() throws Exception {
        // given
        String tokenName = "created-v2-token";
        TokenInstanceRequestDto request = TokenInstanceRequestDtoBuilder
                .aTokenInstanceRequest()
                .withName(tokenName)
                .withConnector(connector.getUuid().toString())
                .build();
        String connectedStatusResponse = "{\"status\":\"Connected\"}";
        String emptyScopedRequest = "{\"tokenAttributes\":[]}";
        connectorMock.stubTokenStatusWithAttributes(connectedStatusResponse, emptyScopedRequest);

        // when
        TokenInstanceDetailDto detail = tokenInstanceService.createTokenInstance(request);

        // then
        assertEquals(tokenName, detail.getName());
        TokenInstanceReference persisted = findToken(tokenName);
        flushAndClear();
        TokenInstanceReference reloaded = tokenInstanceReferenceRepository.findById(persisted.getUuid()).orElseThrow();
        assertEquals(connectorInterface.getUuid(), reloaded.getConnectorInterfaceUuid());
        assertEquals(TokenInstanceStatus.CONNECTED, reloaded.getStatus());
        connectorMock.verifyScopedTokenStatusRequest(emptyScopedRequest);
    }

    @Test
    void listTokenProfileAttributes_sendsStoredScopedAttributes() throws Exception {
        // given
        String attributeName = "profile-scope-label";
        String attributeValue = "persisted-profile-scope-value";
        TokenInstanceReference token = persistToken("existing-v2-token");
        persistTokenAttribute(token, attributeName, attributeValue);
        String expectedScopedRequest = "{\"tokenAttributes\":[{\"name\":\"" + attributeName
                + "\",\"content\":[{\"data\":\"" + attributeValue + "\"}]}]}";

        // when
        List<BaseAttribute> attributes = tokenInstanceService
                .listTokenProfileAttributes(SecuredUUID.fromUUID(token.getUuid()));

        // then
        assertNotNull(attributes);
        connectorMock.verifyScopedTokenProfileAttributesRequestContaining(expectedScopedRequest);
    }

    @Test
    void reloadStatus_sendsPersistedTokenAttributes_andPersistsConnectorStatus() throws Exception {
        // given
        String attributeName = "token-label";
        String attributeValue = "persisted-token-value";
        String connectedStatusResponse = "{\"status\":\"Connected\"}";
        TokenInstanceReference token = persistToken("persisted-attributes-token");
        persistTokenAttribute(token, attributeName, attributeValue);
        connectorMock.stubTokenStatus(connectedStatusResponse);
        flushAndClear();

        // when
        tokenInstanceService.reloadStatus(SecuredUUID.fromUUID(token.getUuid()));

        // then
        flushAndClear();
        TokenInstanceReference reloaded = tokenInstanceReferenceRepository.findById(token.getUuid()).orElseThrow();
        assertEquals(TokenInstanceStatus.CONNECTED, reloaded.getStatus());
        String expectedScopedRequest = "{\"tokenAttributes\":[{\"name\":\"" + attributeName
                + "\",\"content\":[{\"data\":\"" + attributeValue + "\"}]}]}";
        connectorMock.verifyScopedTokenStatusRequestContaining(expectedScopedRequest);
    }

    @Test
    void getTokenInstance_returnsDisconnectedDetailsWhenConnectorIsMissing() throws Exception {
        // given
        String deletedConnectorName = "deleted-token-provider";
        TokenInstanceReference disconnectedToken = new TokenInstanceReference();
        disconnectedToken.setName("disconnected-v2-token");
        disconnectedToken.setConnectorName(deletedConnectorName);
        disconnectedToken.setKind("SOFT");
        disconnectedToken.setStatus(TokenInstanceStatus.UNKNOWN);
        disconnectedToken = tokenInstanceReferenceRepository.save(disconnectedToken);

        // when
        TokenInstanceDetailDto detail = tokenInstanceService
                .getTokenInstance(SecuredUUID.fromUUID(disconnectedToken.getUuid()));

        // then
        assertEquals(TokenInstanceStatus.DISCONNECTED, detail.getStatus().getStatus());
        assertEquals(deletedConnectorName + " (Deleted)", detail.getConnectorName());
        assertEquals("", detail.getConnectorUuid());
    }

    @Test
    void updateTokenInstance_persistsRefreshedV2Status() throws Exception {
        // given
        String tokenName = "updated-v2-token";
        TokenInstanceReference token = persistToken(tokenName);
        TokenInstanceRequestDto request = TokenInstanceRequestDtoBuilder
                .aTokenInstanceRequest()
                .withName("requested-v2-name")
                .withConnector(connector.getUuid().toString())
                .build();

        // when
        TokenInstanceDetailDto detail = tokenInstanceService
                .updateTokenInstance(SecuredUUID.fromUUID(token.getUuid()), request);

        // then
        assertNotNull(detail);
        flushAndClear();
        TokenInstanceReference reloaded = tokenInstanceReferenceRepository.findById(token.getUuid()).orElseThrow();
        assertEquals(TokenInstanceStatus.CONNECTED, reloaded.getStatus());
    }

    @Test
    void deleteTokenInstance_removesLocalReferenceWithoutRemoteLifecycle() throws Exception {
        // given
        TokenInstanceReference token = persistToken("local-only-v2-token");

        // when
        tokenInstanceService.deleteTokenInstance(SecuredUUID.fromUUID(token.getUuid()));

        // then
        flushAndClear();
        assertFalse(tokenInstanceReferenceRepository.findById(token.getUuid()).isPresent());
    }

    @Test
    void listTokenInstanceActivationAttributes_returnsEmptyForV2Provider() throws Exception {
        // given
        TokenInstanceReference token = persistToken("v2-activation-attributes-token");

        // when
        List<BaseAttribute> attributes = tokenInstanceService
                .listTokenInstanceActivationAttributes(SecuredUUID.fromUUID(token.getUuid()));

        // then
        assertNotNull(attributes);
        assertTrue(attributes.isEmpty());
    }

    @Test
    void validateTokenProfileAttributes_acceptsNullAttributesForV2Provider() throws Exception {
        // given
        TokenInstanceReference token = persistToken("v2-profile-validation-token");
        String emptyScopedRequest = "{\"tokenAttributes\":[]}";

        // when
        tokenInstanceInternalService.validateTokenProfileAttributes(SecuredUUID.fromUUID(token.getUuid()), null);

        // then
        connectorMock.verifyScopedTokenProfileAttributesRequest(emptyScopedRequest);
    }

    @Test
    void listSupportedKeyUsages_returnsConnectorValues_withTokenScope() throws Exception {
        // given
        String attributeName = "key-usage-scope-label";
        String attributeValue = "persisted-key-usage-scope-value";
        String responseJson = "[\"sign\",\"encrypt\"]";
        TokenInstanceReference token = persistToken("v2-key-usages-token");
        persistTokenAttribute(token, attributeName, attributeValue);
        connectorMock.stubTokenProfileKeyUsages(responseJson);
        String expectedScopedRequest = "{\"tokenAttributes\":[{\"name\":\"" + attributeName
                + "\",\"content\":[{\"data\":\"" + attributeValue + "\"}]}]}";

        // when
        List<KeyUsage> usages = tokenInstanceService.listSupportedKeyUsages(token.getSecuredUuid());

        // then
        assertEquals(List.of(KeyUsage.SIGN, KeyUsage.ENCRYPT), usages);
        connectorMock.verifyScopedTokenProfileKeyUsagesRequestContaining(expectedScopedRequest);
    }

    @Test
    void listSupportedKeyUsages_returnsEmptyList_forMissingBody() throws Exception {
        // given
        String emptyScopedRequest = "{\"tokenAttributes\":[]}";
        TokenInstanceReference token = persistToken("v2-missing-key-usages-token");
        connectorMock.stubTokenProfileKeyUsagesWithoutBody();

        // when
        List<KeyUsage> usages = tokenInstanceService.listSupportedKeyUsages(token.getSecuredUuid());

        // then
        assertTrue(usages.isEmpty());
        connectorMock.verifyScopedTokenProfileKeyUsagesRequest(emptyScopedRequest);
    }

    @Test
    void listSupportedKeyUsages_throwsConnectorException_forConnectorError() {
        // given
        String emptyScopedRequest = "{\"tokenAttributes\":[]}";
        TokenInstanceReference token = persistToken("v2-key-usages-error-token");
        connectorMock.stubTokenProfileKeyUsagesError();

        // when
        Executable listUsages = () -> tokenInstanceService.listSupportedKeyUsages(token.getSecuredUuid());

        // then
        assertThrows(ConnectorException.class, listUsages);
        connectorMock.verifyScopedTokenProfileKeyUsagesRequest(emptyScopedRequest);
    }

    @Test
    void createTokenInstance_rejectsMalformedConnectorUuid() {
        // given
        String malformedConnectorUuid = "not-a-uuid";
        TokenInstanceRequestDto request = TokenInstanceRequestDtoBuilder
                .aTokenInstanceRequest()
                .withName("malformed-connector-token")
                .withConnector(malformedConnectorUuid)
                .build();

        // when
        Executable create = () -> tokenInstanceService.createTokenInstance(request);

        // then
        assertThrows(ValidationException.class, create);
    }

    @Test
    void activateTokenInstance_isNoOpForV2Provider() throws Exception {
        // given
        TokenInstanceReference token = persistToken("v2-activation-token");

        // when
        tokenInstanceService.activateTokenInstance(SecuredUUID.fromUUID(token.getUuid()), List.of());

        // then
        flushAndClear();
        assertEquals(TokenInstanceStatus.UNKNOWN,
                tokenInstanceReferenceRepository.findById(token.getUuid()).orElseThrow().getStatus());
    }

    @Test
    void deactivateTokenInstance_isNoOpForV2Provider() throws Exception {
        // given
        TokenInstanceReference token = persistToken("v2-deactivation-token");

        // when
        tokenInstanceService.deactivateTokenInstance(SecuredUUID.fromUUID(token.getUuid()));

        // then
        flushAndClear();
        assertEquals(TokenInstanceStatus.UNKNOWN,
                tokenInstanceReferenceRepository.findById(token.getUuid()).orElseThrow().getStatus());
    }

    @Test
    void listTokenInstances_returnsPersistedV2Token() {
        // given
        TokenInstanceReference token = persistToken("listed-v2-token");

        // when
        List<TokenInstanceDto> tokens = tokenInstanceService.listTokenInstances(SecurityFilter.create());

        // then
        assertEquals(1, tokens.size());
        assertEquals(token.getUuid().toString(), tokens.get(0).getUuid());
    }

    @Test
    void getTokenInstanceEntity_returnsExistingV2Token() throws Exception {
        // given
        TokenInstanceReference token = persistToken("entity-v2-token");

        // when
        TokenInstanceReference result = tokenInstanceInternalService
                .getTokenInstanceEntity(SecuredUUID.fromUUID(token.getUuid()));

        // then
        assertEquals(token.getUuid(), result.getUuid());
    }

    @Test
    void getResourceObjectInternal_returnsPersistedV2Token() throws Exception {
        // given
        String tokenName = "resource-v2-token";
        TokenInstanceReference token = persistToken(tokenName);

        // when
        NameAndUuidDto internalResult = tokenInstanceInternalService.getResourceObjectInternal(token.getUuid());

        // then
        assertEquals(token.getUuid().toString(), internalResult.getUuid());
        assertEquals(tokenName, internalResult.getName());
    }

    @Test
    void getResourceObjectExternal_returnsPersistedV2Token() throws Exception {
        // given
        String tokenName = "external-resource-v2-token";
        TokenInstanceReference token = persistToken(tokenName);

        // when
        NameAndUuidDto result = tokenInstanceInternalService
                .getResourceObjectExternal(SecuredUUID.fromUUID(token.getUuid()));

        // then
        assertEquals(token.getUuid().toString(), result.getUuid());
        assertEquals(tokenName, result.getName());
    }

    @Test
    void listResourceObjects_returnsPersistedV2Token() {
        // given
        TokenInstanceReference token = persistToken("listed-resource-v2-token");

        // when
        List<NameAndUuidDto> results = tokenInstanceInternalService
                .listResourceObjects(SecurityFilter.create(), null, null);

        // then
        assertEquals(1, results.size());
        assertEquals(token.getUuid().toString(), results.get(0).getUuid());
    }

    @Test
    void evaluatePermissionChain_acceptsExistingV2Token() throws Exception {
        // given
        TokenInstanceReference token = persistToken("permission-v2-token");

        // when
        Executable evaluate = () -> tokenInstanceInternalService
                .evaluatePermissionChain(SecuredUUID.fromUUID(token.getUuid()));

        // then
        assertDoesNotThrow(evaluate);
    }

    @Test
    void bulkDelete_removesV2Token() throws Exception {
        // given
        TokenInstanceReference token = persistToken("bulk-delete-v2-token");

        // when
        tokenInstanceService.deleteTokenInstance(List.of(SecuredUUID.fromUUID(token.getUuid())));

        // then
        flushAndClear();
        assertFalse(tokenInstanceReferenceRepository.findById(token.getUuid()).isPresent());
    }

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("token-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface(Connector owner) {
        ConnectorInterfaceEntity value = new ConnectorInterfaceEntity();
        value.setConnector(owner);
        value.setConnectorUuid(owner.getUuid());
        value.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        value.setVersion("v2");
        value.setFeatures(List.of(FeatureFlag.STATELESS));
        value = connectorInterfaceRepository.save(value);
        owner.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistToken(String name) {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName(name);
        value.setConnector(connector);
        value.setConnectorInterface(connectorInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.UNKNOWN);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenInstanceReference findToken(String name) {
        return tokenInstanceReferenceRepository
                .findAll()
                .stream()
                .filter(reference -> name.equals(reference.getName()))
                .findFirst()
                .orElseThrow();
    }

    private void persistTokenAttribute(TokenInstanceReference token, String name, String value) throws Exception {
        UUID attributeUuid = UUID.randomUUID();
        attributeEngine
                .updateDataAttributeDefinitions(connector.getUuid(), null, List
                        .of(DataAttributeV3Builder.aDataAttribute().withUuid(attributeUuid).withName(name).build()));
        RequestAttributeV3 request = new RequestAttributeV3(attributeUuid, name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(value)));
        attributeEngine
                .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN, token.getUuid())
                        .connector(connector.getUuid())
                        .build(), List.of(request));
    }

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }
}
