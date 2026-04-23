package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.czertainly.api.model.core.cryptography.token.TokenInstanceDto;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
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
class TokenInstanceServiceTest extends BaseSpringBootTest {

    private static final String AUTHORITY_INSTANCE_NAME = "testTokenInstance1";

    @Autowired
    private TokenInstanceService tokenInstanceService;

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
        Assertions.assertEquals(tokenInstanceReference.getConnector().getUuid().toString(), dto.getConnectorUuid());
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
        Assertions.assertEquals(tokenInstanceReference.getConnector().getUuid().toString(), dto.getConnectorUuid());
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

        tokenInstanceService.listTokenProfileAttributes(tokenInstanceReference.getSecuredUuid());
    }

    @Test
    void testGetTokenProfileActivationAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes"))
                .willReturn(WireMock.ok()));

        tokenInstanceService.listTokenInstanceActivationAttributes(tokenInstanceReference.getSecuredUuid());
    }

    @Test
    void testActivateTokenInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes"))
                .willReturn(WireMock.ok()));

        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate/attributes/validate"))
                .willReturn(WireMock.ok()));

        mockServer.stubFor(WireMock
                .patch(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/activate"))
                .willReturn(WireMock.ok()));

        tokenInstanceService.activateTokenInstance(tokenInstanceReference.getSecuredUuid(), List.of());
    }

    @Test
    void testDeactivateTokenInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .patch(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/deactivate"))
                .willReturn(WireMock.ok()));

        tokenInstanceService.deactivateTokenInstance(tokenInstanceReference.getSecuredUuid());
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

        tokenInstanceService.validateTokenProfileAttributes(tokenInstanceReference.getSecuredUuid(), List.of());
    }

    @Test
    void testValidateTokenProfileAttributes_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenInstanceService.validateTokenProfileAttributes(
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
        List<NameAndUuidDto> response = tokenInstanceService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, response.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = tokenInstanceService.getResourceObjectInternal(tokenInstanceReference.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = tokenInstanceService.getResourceObjectExternal(tokenInstanceReference.getSecuredUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenInstanceReference.getName(), nameAndUuidDto.getName());
    }
}
