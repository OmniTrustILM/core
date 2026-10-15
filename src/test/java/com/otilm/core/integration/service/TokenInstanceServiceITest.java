package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenInstanceInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.MetaDefinitions;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
@Rollback
class TokenInstanceServiceITest extends BaseSpringBootTest {

    private static final String AUTHORITY_INSTANCE_NAME = "testTokenInstance1";

    @Autowired
    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    private TokenInstanceInternalService tokenInstanceInternalService;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private TokenInstanceReference tokenInstanceReference;
    private Connector connector;
    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();

        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());

        connector = new Connector();
        connector.setName("tokenInstanceConnector");
        connector.setUrl(LoopbackWireMock.url(mockServer));
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("Soft")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName(AUTHORITY_INSTANCE_NAME);
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setConnectorUuid(connector.getUuid());
        tokenInstanceReference.setKind("sample");
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setStatus(TokenInstanceStatus.UNKNOWN);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListTokenInstances() {
        List<TokenInstanceDto> tokenInstances = tokenInstanceService.listTokenInstances(SecurityFilter.create());
        Assertions.assertNotNull(tokenInstances);
        Assertions.assertFalse(tokenInstances.isEmpty());
        Assertions.assertEquals(1, tokenInstances.size());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), tokenInstances.get(0).getUuid());
    }

    @Test
    void listTokenAttributes_forwardsRequestedKindToV1Provider() throws Exception {
        // given
        String requestedKind = "Soft";
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));

        // when
        List<?> attributes = tokenInstanceService
                .listTokenAttributes(SecuredUUID.fromUUID(connector.getUuid()), requestedKind);

        // then
        Assertions.assertNotNull(attributes);
        mockServer
                .verify(WireMock
                        .getRequestedFor(
                                WireMock.urlPathEqualTo("/v1/cryptographyProvider/" + requestedKind + "/attributes")));
    }

    @Test
    void testGetTokenInstance() throws ConnectorException, NotFoundException {
        // given
        String activatedStatusResponse = "{\"status\":\"Activated\",\"components\":{\"hsm\":{\"status\":\"Connected\"}}}";
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .willReturn(WireMock.okJson("{}")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.okJson(activatedStatusResponse)));

        // when
        TokenInstanceDetailDto dto = tokenInstanceService.getTokenInstance(tokenInstanceReference.getSecuredUuid());

        // then
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(tokenInstanceReference.getConnectorUuid().toString(), dto.getConnectorUuid());
        Assertions.assertEquals(TokenInstanceStatus.ACTIVATED, dto.getStatus().getStatus());
        Assertions.assertEquals(TokenInstanceStatus.CONNECTED, dto.getStatus().getComponents().get("hsm").getStatus());
    }

    @Test
    void getTokenInstance_returnsWarningWhenStatusRefreshFails() throws Exception {
        // given
        String connectorFailureBody = "status refresh failed";
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.aResponse().withStatus(500).withBody(connectorFailureBody)));

        // when
        TokenInstanceDetailDto detail = tokenInstanceService.getTokenInstance(tokenInstanceReference.getSecuredUuid());

        // then
        Assertions.assertEquals(TokenInstanceStatus.WARNING, detail.getStatus().getStatus());
        Assertions
                .assertEquals(TokenInstanceStatus.WARNING,
                        tokenInstanceReferenceRepository
                                .findById(tokenInstanceReference.getUuid())
                                .orElseThrow()
                                .getStatus());
    }

    @Test
    void getTokenInstance_returnsDisconnectedDetailsWhenConnectorIsMissing() throws Exception {
        // given
        String deletedConnectorName = "deleted-token-provider";
        TokenInstanceReference disconnectedToken = new TokenInstanceReference();
        disconnectedToken.setName("disconnected-token");
        disconnectedToken.setConnectorName(deletedConnectorName);
        disconnectedToken.setKind("Soft");
        disconnectedToken.setStatus(TokenInstanceStatus.UNKNOWN);
        disconnectedToken = tokenInstanceReferenceRepository.save(disconnectedToken);

        // when
        TokenInstanceDetailDto detail = tokenInstanceService.getTokenInstance(disconnectedToken.getSecuredUuid());

        // then
        Assertions.assertEquals(TokenInstanceStatus.DISCONNECTED, detail.getStatus().getStatus());
        Assertions.assertEquals(deletedConnectorName + " (Deleted)", detail.getConnectorName());
        Assertions.assertEquals("", detail.getConnectorUuid());
    }

    @Test
    void reloadStatus_persistsConnectorStatusForV1Provider() throws Exception {
        // given
        String connectedStatusResponse = "{\"status\":\"Connected\",\"components\":{\"hsm\":{\"status\":\"Connected\"}}}";
        tokenInstanceReference.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.okJson(connectedStatusResponse)));

        // when
        TokenInstanceDetailDto detail = tokenInstanceService.reloadStatus(tokenInstanceReference.getSecuredUuid());

        // then
        Assertions.assertEquals(TokenInstanceStatus.CONNECTED, detail.getStatus().getStatus());
        Assertions
                .assertEquals(TokenInstanceStatus.CONNECTED, detail.getStatus().getComponents().get("hsm").getStatus());
        Assertions
                .assertEquals(TokenInstanceStatus.CONNECTED,
                        tokenInstanceReferenceRepository
                                .findById(tokenInstanceReference.getUuid())
                                .orElseThrow()
                                .getStatus());
    }

    @Test
    void testGetTokenInstance_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenInstanceService
                        .getTokenInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddTokenInstance()
            throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens"))
                        .willReturn(WireMock.okJson("{ \"uuid\": \"abfbc322-29e1-11ed-a261-0242ac120003\" }")));

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock
                                .okJson("{\"status\":\"Connected\",\"components\":{\"hsm\":{\"status\":\"Connected\"}}}")));

        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName("testTokenInstance2");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("Soft");

        TokenInstanceDetailDto dto = tokenInstanceService.createTokenInstance(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(tokenInstanceReference.getConnectorUuid().toString(), dto.getConnectorUuid());
        Assertions.assertEquals(TokenInstanceStatus.CONNECTED, dto.getStatus().getComponents().get("hsm").getStatus());
    }

    @Test
    void testAddTokenInstance_acceptsOpaqueTokenIdentifierFromConnector() throws Exception {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens"))
                        .willReturn(WireMock.okJson("{ \"uuid\": \"not-a-valid-uuid\" }")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.okJson("{}")));

        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName("testTokenInstance3");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("Soft");

        TokenInstanceDetailDto detail = tokenInstanceService.createTokenInstance(request);
        Assertions.assertEquals(request.getName(), detail.getName());
        Assertions
                .assertEquals("not-a-valid-uuid",
                        tokenInstanceReferenceRepository
                                .findAll()
                                .stream()
                                .filter(reference -> request.getName().equals(reference.getName()))
                                .findFirst()
                                .orElseThrow()
                                .getTokenInstanceUuid());
    }

    @Test
    void testAddTokenInstance_notFound() {
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName("Demo");
        request.setConnectorUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        Assertions.assertThrows(NotFoundException.class, () -> tokenInstanceService.createTokenInstance(request));
    }

    @Test
    void testAddTokenInstance_alreadyExist() {
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName(AUTHORITY_INSTANCE_NAME); // authorityInstance with same name exist

        Assertions.assertThrows(AlreadyExistException.class, () -> tokenInstanceService.createTokenInstance(request));
    }

    @Test
    void createTokenInstance_rejectsMalformedConnectorUuid() {
        // given
        String malformedConnectorUuid = "not-a-uuid";
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName("malformed-connector-token");
        request.setConnectorUuid(malformedConnectorUuid);

        // when
        Executable create = () -> tokenInstanceService.createTokenInstance(request);

        // then
        Assertions.assertThrows(ValidationException.class, create);
    }

    @Test
    void createTokenInstance_keepsCreatedReferenceWhenInitialStatusLookupFails() throws Exception {
        // given
        UUID remoteTokenUuid = UUID.randomUUID();
        String tokenName = "created-without-status";
        stubTokenInstanceCreation(remoteTokenUuid, 500);
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName(tokenName);
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("Soft");

        // when
        TokenInstanceDetailDto detail = tokenInstanceService.createTokenInstance(request);

        // then
        Assertions.assertEquals(tokenName, detail.getName());
        TokenInstanceReference persisted = tokenInstanceReferenceRepository.findByName(tokenName).orElseThrow();
        Assertions.assertEquals(remoteTokenUuid.toString(), persisted.getTokenInstanceUuid());
        Assertions.assertEquals(TokenInstanceStatus.WARNING, persisted.getStatus());
    }

    @Test
    void testEditTokenInstance_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenInstanceService
                        .updateTokenInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void updateTokenInstance_forwardsRequestedNameToRemoteProvider() throws Exception {
        // given
        String updatedTokenName = "updated-token-instance";
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock
                                .okJson("{\"status\":\"Activated\",\"components\":{\"hsm\":{\"status\":\"Connected\"}}}")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .withRequestBody(WireMock.matchingJsonPath("$.name", WireMock.equalTo(updatedTokenName)))
                        .willReturn(WireMock.okJson("{\"uuid\":\"1l\"}")));
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName(updatedTokenName);
        request.setKind("Soft");
        request.setAttributes(List.of());

        // when
        TokenInstanceDetailDto detail = tokenInstanceService
                .updateTokenInstance(tokenInstanceReference.getSecuredUuid(), request);

        // then
        Assertions.assertNotNull(detail);
        Assertions
                .assertEquals(TokenInstanceStatus.CONNECTED, detail.getStatus().getComponents().get("hsm").getStatus());
        mockServer
                .verify(WireMock
                        .postRequestedFor(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .withRequestBody(WireMock.matchingJsonPath("$.name", WireMock.equalTo(updatedTokenName))));
    }

    @Test
    void testRemoveTokenInstance() throws NotFoundException {
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .willReturn(WireMock.ok()));

        tokenInstanceService.deleteTokenInstance(tokenInstanceReference.getSecuredUuid());
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenInstanceService.getTokenInstance(tokenInstanceReference.getSecuredUuid()));
    }

    @Test
    void deleteTokenInstance_rejectsTokenWithAssociatedProfile() {
        // given
        TokenProfile dependentProfile = new TokenProfile();
        dependentProfile.setName("dependent-profile");
        dependentProfile.setTokenInstanceReference(tokenInstanceReference);
        dependentProfile.setEnabled(true);
        tokenProfileRepository.save(dependentProfile);

        // when
        Executable delete = () -> tokenInstanceService.deleteTokenInstance(tokenInstanceReference.getSecuredUuid());

        // then
        Assertions.assertThrows(ValidationException.class, delete);
        Assertions.assertTrue(tokenInstanceReferenceRepository.findById(tokenInstanceReference.getUuid()).isPresent());
    }

    @Test
    void testGetTokenProfileAttributes() throws ConnectorException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                        .willReturn(WireMock.ok()));

        var attributes = tokenInstanceService.listTokenProfileAttributes(tokenInstanceReference.getSecuredUuid());
        Assertions.assertTrue(attributes.isEmpty());
    }

    @Test
    void testGetTokenProfileActivationAttributes() throws ConnectorException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes"))
                        .willReturn(WireMock.ok()));

        var attributes = tokenInstanceService
                .listTokenInstanceActivationAttributes(tokenInstanceReference.getSecuredUuid());
        Assertions.assertTrue(attributes.isEmpty());
    }

    @Test
    void testActivateTokenInstance() {
        // given
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes"))
                        .willReturn(WireMock.ok()));

        mockServer
                .stubFor(WireMock
                        .get(WireMock
                                .urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes/validate"))
                        .willReturn(WireMock.ok()));

        mockServer
                .stubFor(WireMock
                        .patch(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate"))
                        .willReturn(WireMock.ok()));

        var securedUuid = tokenInstanceReference.getSecuredUuid();

        // when
        Assertions.assertDoesNotThrow(() -> tokenInstanceService.activateTokenInstance(securedUuid, List.of()));

        // then
        Assertions
                .assertEquals(TokenInstanceStatus.ACTIVATED,
                        tokenInstanceReferenceRepository
                                .findById(tokenInstanceReference.getUuid())
                                .orElseThrow()
                                .getStatus());
    }

    @Test
    void testDeactivateTokenInstance() {
        // given
        mockServer
                .stubFor(WireMock
                        .patch(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/deactivate"))
                        .willReturn(WireMock.ok()));

        var securedUuid = tokenInstanceReference.getSecuredUuid();

        // when
        Assertions.assertDoesNotThrow(() -> tokenInstanceService.deactivateTokenInstance(securedUuid));

        // then
        Assertions
                .assertEquals(TokenInstanceStatus.DEACTIVATED,
                        tokenInstanceReferenceRepository
                                .findById(tokenInstanceReference.getUuid())
                                .orElseThrow()
                                .getStatus());
    }

    @Test
    void testGetTokenProfileAttributes_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenInstanceService
                        .listTokenProfileAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testValidateTokenProfileAttributes() throws ConnectorException, NotFoundException, AttributeException {
        // given
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                        .willReturn(WireMock.ok()));

        // when
        tokenInstanceInternalService.validateTokenProfileAttributes(tokenInstanceReference.getSecuredUuid(), null);

        // then
        mockServer
                .verify(WireMock
                        .postRequestedFor(WireMock
                                .urlPathMatching(
                                        "/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate")));
    }

    @Test
    void testValidateTokenProfileAttributes_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenInstanceInternalService
                                .validateTokenProfileAttributes(
                                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void getTokenInstanceEntity_returnsExistingToken() throws Exception {
        // given
        SecuredUUID tokenUuid = tokenInstanceReference.getSecuredUuid();

        // when
        TokenInstanceReference result = tokenInstanceInternalService.getTokenInstanceEntity(tokenUuid);

        // then
        Assertions.assertEquals(tokenInstanceReference.getUuid(), result.getUuid());
    }

    @Test
    void evaluatePermissionChain_acceptsExistingToken() throws Exception {
        // given
        SecuredUUID tokenUuid = tokenInstanceReference.getSecuredUuid();

        // when
        Executable evaluate = () -> tokenInstanceInternalService.evaluatePermissionChain(tokenUuid);

        // then
        Assertions.assertDoesNotThrow(evaluate);
    }

    @Test
    void testRemoveTokenInstance_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenInstanceService
                        .deleteTokenInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() {
        // given
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .willReturn(WireMock.ok()));

        // when
        tokenInstanceService.deleteTokenInstance(List.of(tokenInstanceReference.getSecuredUuid()));

        // then
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenInstanceService.deleteTokenInstance(tokenInstanceReference.getSecuredUuid()));
    }

    @Test
    void bulkDelete_continuesAfterMissingToken() {
        // given
        String missingTokenUuid = "abfbc322-29e1-11ed-a261-0242ac120002";
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .willReturn(WireMock.ok()));
        SecuredUUID missingToken = SecuredUUID.fromString(missingTokenUuid);

        // when
        tokenInstanceService.deleteTokenInstance(List.of(missingToken, tokenInstanceReference.getSecuredUuid()));

        // then
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenInstanceService.getTokenInstance(tokenInstanceReference.getSecuredUuid()));
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> response = tokenInstanceInternalService
                .listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, response.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = tokenInstanceInternalService
                .getResourceObjectInternal(tokenInstanceReference.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = tokenInstanceInternalService
                .getResourceObjectExternal(tokenInstanceReference.getSecuredUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testDeleteTokenInstance_connectorError_entityNotDeleted() {
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.anyUrl())
                        .willReturn(WireMock.aResponse().withStatus(500).withBody("Simulated connector error")));

        tokenInstanceService.deleteTokenInstance(List.of(tokenInstanceReference.getSecuredUuid()));

        Assertions
                .assertTrue(tokenInstanceReferenceRepository.findById(tokenInstanceReference.getUuid()).isPresent(),
                        "Entity must remain in DB because the connector returned 500 and the catch block absorbed the error");
    }

    private void stubTokenInstanceCreation(UUID remoteTokenUuid, int statusCode) {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v1/cryptographyProvider/tokens"))
                        .willReturn(WireMock.okJson("{\"uuid\":\"" + remoteTokenUuid + "\"}")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.aResponse().withStatus(statusCode)));
    }
}
