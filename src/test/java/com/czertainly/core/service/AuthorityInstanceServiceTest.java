package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.authority.AuthorityInstanceRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.NameAndIdDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.authority.AuthorityInstanceDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
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

import java.util.List;
import java.util.UUID;

class AuthorityInstanceServiceTest extends BaseSpringBootTest {

    private static final String AUTHORITY_INSTANCE_NAME = "testAuthorityInstance1";

    @Autowired
    private AuthorityInstanceService authorityInstanceService;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private AuthorityInstanceReference authorityInstance;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName(AUTHORITY_INSTANCE_NAME);
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListAuthorityInstances() {
        List<AuthorityInstanceDto> authorityInstances = authorityInstanceService.listAuthorityInstances(SecurityFilter.create());
        Assertions.assertNotNull(authorityInstances);
        Assertions.assertFalse(authorityInstances.isEmpty());
        Assertions.assertEquals(1, authorityInstances.size());
        Assertions.assertEquals(authorityInstance.getUuid().toString(), authorityInstances.get(0).getUuid());
    }

    @Test
    void testGetAuthorityInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+"))
                .willReturn(WireMock.okJson("{}")));

        AuthorityInstanceDto dto = authorityInstanceService.getAuthorityInstance(authorityInstance.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(authorityInstance.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(authorityInstance.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testGetAuthorityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.getAuthorityInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddAuthorityInstance() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities"))
                .willReturn(WireMock.okJson("{ \"id\": 2 }")));

        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        request.setName("testAuthorityInstance2");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("Ejbca");

        AuthorityInstanceDto dto = authorityInstanceService.createAuthorityInstance(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(authorityInstance.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testAddAuthorityInstance_notFound() {
        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        request.setName("Demo");
        request.setConnectorUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        // connector uui not set
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.createAuthorityInstance(request));
    }

    @Test
    void testAddAuthorityInstance_alreadyExist() {
        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        request.setName(AUTHORITY_INSTANCE_NAME); // authorityInstance with same name exist

        Assertions.assertThrows(AlreadyExistException.class, () -> authorityInstanceService.createAuthorityInstance(request));
    }

    @Test
    void testEditAuthorityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.editAuthorityInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testEditAuthorityInstance() throws ConnectorException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+"))
                .willReturn(WireMock.okJson("{}")));

        AuthorityInstanceUpdateRequestDto request = new AuthorityInstanceUpdateRequestDto();
        request.setAttributes(List.of());
        request.setCustomAttributes(List.of());

        AuthorityInstanceDto dto = authorityInstanceService.editAuthorityInstance(authorityInstance.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(authorityInstance.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(authorityInstance.getName(), dto.getName());
    }

    @Test
    void testRemoveAuthorityInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .delete(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+"))
                .willReturn(WireMock.ok()));

        authorityInstanceService.deleteAuthorityInstance(authorityInstance.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.getAuthorityInstance(authorityInstance.getSecuredUuid()));
    }

    @Test
    void testGetRaProfileAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.ok()));

        authorityInstanceService.listRAProfileAttributes(authorityInstance.getSecuredUuid());
    }

    @Test
    void testGetRaProfileAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.listRAProfileAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testValidateRaProfileAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        authorityInstanceService.validateRAProfileAttributes(authorityInstance.getSecuredUuid(), List.of());
    }

    @Test
    void testValidateRaProfileAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.validateRAProfileAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testRemoveAuthorityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.deleteAuthorityInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() throws ConnectorException {
        authorityInstanceService.bulkDeleteAuthorityInstance(List.of(authorityInstance.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.getAuthorityInstance(authorityInstance.getSecuredUuid()));
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = authorityInstanceService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = authorityInstanceService.getResourceObjectInternal(authorityInstance.getUuid());
        Assertions.assertEquals(authorityInstance.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(authorityInstance.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = authorityInstanceService.getResourceObjectExternal(authorityInstance.getSecuredUuid());
        Assertions.assertEquals(authorityInstance.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(authorityInstance.getName(), nameAndUuidDto.getName());

    }

    @Test
    void testListCertificateProfiles() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/endEntityProfiles/[0-9]+/certificateprofiles"))
                .willReturn(WireMock.okJson("[{\"id\":1,\"name\":\"profileA\"},{\"id\":2,\"name\":\"profileB\"}]")));

        List<NameAndIdDto> profiles = authorityInstanceService.listCertificateProfiles(authorityInstance.getSecuredUuid(), 42);

        Assertions.assertNotNull(profiles);
        Assertions.assertEquals(2, profiles.size());
        Assertions.assertEquals(1, profiles.get(0).getId());
        Assertions.assertEquals("profileA", profiles.get(0).getName());
        Assertions.assertEquals(2, profiles.get(1).getId());
        Assertions.assertEquals("profileB", profiles.get(1).getName());
    }

    @Test
    void testListCertificateProfiles_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.listCertificateProfiles(
                SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), 42));
    }

    @Test
    void testListCAsInProfile() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/endEntityProfiles/[0-9]+/cas"))
                .willReturn(WireMock.okJson("[{\"id\":10,\"name\":\"RootCA\"},{\"id\":11,\"name\":\"IssuingCA\"}]")));

        List<NameAndIdDto> cas = authorityInstanceService.listCAsInProfile(authorityInstance.getSecuredUuid(), 42);

        Assertions.assertNotNull(cas);
        Assertions.assertEquals(2, cas.size());
        Assertions.assertEquals(10, cas.get(0).getId());
        Assertions.assertEquals("RootCA", cas.get(0).getName());
        Assertions.assertEquals(11, cas.get(1).getId());
        Assertions.assertEquals("IssuingCA", cas.get(1).getName());
    }

    @Test
    void testListCAsInProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> authorityInstanceService.listCAsInProfile(
                SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), 42));
    }

    @Test
    void testBulkDeleteAuthorityInstance_connectorError_returnsErrorMessage() throws ValidationException, ConnectorException {
        mockServer.stubFor(WireMock.delete(WireMock.anyUrl())
                .willReturn(WireMock.aResponse().withStatus(500).withBody("Simulated connector error")));

        List<BulkActionMessageDto> messages = authorityInstanceService
                .bulkDeleteAuthorityInstance(List.of(authorityInstance.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(authorityInstance.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
        Assertions.assertTrue(authorityInstanceReferenceRepository.findByUuid(authorityInstance.getUuid()).isPresent(),
                "Entity should remain in DB because delete failed");
    }

    @Test
    void testForceDeleteAuthorityInstance_nonExistentUuid_returnsErrorMessage() throws ValidationException, NotFoundException {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = authorityInstanceService.forceDeleteAuthorityInstance(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testForceDeleteAuthorityInstance_connectorError_returnsErrorWithEntityName() throws ValidationException, NotFoundException {
        mockServer.stubFor(WireMock.delete(WireMock.anyUrl())
                .willReturn(WireMock.aResponse().withStatus(500).withBody("Connector error")));

        List<BulkActionMessageDto> messages = authorityInstanceService
                .forceDeleteAuthorityInstance(List.of(authorityInstance.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(authorityInstance.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(authorityInstance.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}
