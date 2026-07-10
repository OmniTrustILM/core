package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenInstanceInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

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
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("tokenInstanceConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
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
    void testGetTokenInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                .willReturn(WireMock.okJson("{}")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                .willReturn(WireMock.okJson("{}")));

        TokenInstanceDetailDto dto = tokenInstanceService.getTokenInstance(tokenInstanceReference.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(tokenInstanceReference.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testGetTokenInstance_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenInstanceService.getTokenInstance(
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")
                )
        );
    }

    @Test
    void testAddTokenInstance() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens"))
                .willReturn(WireMock.okJson("{ \"uuid\": \"abfbc322-29e1-11ed-a261-0242ac120003\" }")));

        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                .willReturn(WireMock.okJson("{}")));

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
    }

    @Test
    void testAddTokenInstance_invalidUuidFromConnector() {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens"))
                .willReturn(WireMock.okJson("{ \"uuid\": \"not-a-valid-uuid\" }")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                .willReturn(WireMock.okJson("{}")));

        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setName("testTokenInstance3");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("Soft");

        Assertions.assertThrows(ValidationException.class, () -> tokenInstanceService.createTokenInstance(request));
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
    void testEditTokenInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> tokenInstanceService.updateTokenInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testRemoveTokenInstance() throws NotFoundException {
        mockServer.stubFor(WireMock
                .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                .willReturn(WireMock.ok()));

        tokenInstanceService.deleteTokenInstance(tokenInstanceReference.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> tokenInstanceService.getTokenInstance(tokenInstanceReference.getSecuredUuid()));
    }

    @Test
    void testGetTokenProfileAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                .willReturn(WireMock.ok()));

        var attributes = tokenInstanceService.listTokenProfileAttributes(tokenInstanceReference.getSecuredUuid());
        Assertions.assertTrue(attributes.isEmpty());
    }

    @Test
    void testGetTokenProfileActivationAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes"))
                .willReturn(WireMock.ok()));

        var attributes = tokenInstanceService.listTokenInstanceActivationAttributes(tokenInstanceReference.getSecuredUuid());
        Assertions.assertTrue(attributes.isEmpty());
    }

    @Test
    void testActivateTokenInstance() {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes"))
                .willReturn(WireMock.ok()));

        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes/validate"))
                .willReturn(WireMock.ok()));

        mockServer.stubFor(WireMock
                .patch(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate"))
                .willReturn(WireMock.ok()));

        var securedUuid = tokenInstanceReference.getSecuredUuid();
        Assertions.assertDoesNotThrow(() -> tokenInstanceService.activateTokenInstance(securedUuid, List.of()));
    }

    @Test
    void testDeactivateTokenInstance() {
        mockServer.stubFor(WireMock
                .patch(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/deactivate"))
                .willReturn(WireMock.ok()));

        var securedUuid = tokenInstanceReference.getSecuredUuid();
        Assertions.assertDoesNotThrow(() -> tokenInstanceService.deactivateTokenInstance(securedUuid));
    }

    @Test
    void testGetTokenProfileAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> tokenInstanceService.listTokenProfileAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testValidateTokenProfileAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                .willReturn(WireMock.ok()));

        tokenInstanceInternalService.validateTokenProfileAttributes(tokenInstanceReference.getSecuredUuid(), List.of());
    }

    @Test
    void testValidateTokenProfileAttributes_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenInstanceInternalService.validateTokenProfileAttributes(
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"),
                        null
                )
        );
    }

    @Test
    void testRemoveTokenInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> tokenInstanceService.deleteTokenInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() {
        mockServer.stubFor(WireMock
                .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                .willReturn(WireMock.ok()));
        tokenInstanceService.deleteTokenInstance(List.of(tokenInstanceReference.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> tokenInstanceService.deleteTokenInstance(tokenInstanceReference.getSecuredUuid()));
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> response = tokenInstanceInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, response.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = tokenInstanceInternalService.getResourceObjectInternal(tokenInstanceReference.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = tokenInstanceInternalService.getResourceObjectExternal(tokenInstanceReference.getSecuredUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testDeleteTokenInstance_connectorError_entityNotDeleted() {
        mockServer.stubFor(WireMock.delete(WireMock.anyUrl())
                .willReturn(WireMock.aResponse().withStatus(500).withBody("Simulated connector error")));

        tokenInstanceService.deleteTokenInstance(List.of(tokenInstanceReference.getSecuredUuid()));

        Assertions.assertTrue(
                tokenInstanceReferenceRepository.findById(tokenInstanceReference.getUuid()).isPresent(),
                "Entity must remain in DB because the connector returned 500 and the catch block absorbed the error");
    }
}
