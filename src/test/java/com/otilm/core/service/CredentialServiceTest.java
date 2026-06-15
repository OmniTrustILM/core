package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.credential.CredentialRequestDto;
import com.otilm.api.model.client.credential.CredentialUpdateRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.otilm.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.credential.CredentialDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CredentialRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.Serializable;
import java.util.*;

class CredentialServiceTest extends BaseSpringBootTest {

    private static final String CREDENTIAL_NAME = "testCredential1";

    @Autowired
    private CredentialExternalService credentialService;

    @Autowired
    private CredentialInternalService credentialInternalService;

    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private Credential credential;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("credentialProviderConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        functionGroup.setName(FunctionGroupCode.CREDENTIAL_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        credential = new Credential();
        credential.setKind("sample");
        credential.setName(CREDENTIAL_NAME);
        credential.setConnectorUuid(connector.getUuid());
        credential = credentialRepository.save(credential);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListCredentials() {
        List<CredentialDto> credentials = credentialService.listCredentials(SecurityFilter.create());
        Assertions.assertNotNull(credentials);
        Assertions.assertFalse(credentials.isEmpty());
        Assertions.assertEquals(1, credentials.size());
        Assertions.assertEquals(credential.getUuid().toString(), credentials.get(0).getUuid());
    }

    @Test
    void testGetCredential() throws NotFoundException {
        CredentialDto dto = credentialService.getCredential(credential.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(credential.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(credential.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testGetCredential_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.getCredential(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddCredential() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/credentialProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/credentialProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        CredentialRequestDto request = new CredentialRequestDto();
        request.setName("testCredential2");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("ApiKey");

        CredentialDto dto = credentialService.createCredential(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(credential.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testAddCredential_validationFail() {
        CredentialRequestDto request = new CredentialRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> credentialService.createCredential(request));
    }

    @Test
    void testAddCredential_alreadyExist() {
        CredentialRequestDto request = new CredentialRequestDto();
        request.setName(CREDENTIAL_NAME); // credential with same name exist

        Assertions.assertThrows(AlreadyExistException.class, () -> credentialService.createCredential(request));
    }

    @Test
    void testEditCredential() throws ConnectorException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/credentialProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/credentialProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        CredentialUpdateRequestDto request = new CredentialUpdateRequestDto();
        request.setAttributes(List.of());

        CredentialDto dto = credentialService.editCredential(credential.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(credential.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testEditCredential_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.editCredential(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testRemoveCredential() throws NotFoundException {
        credentialService.deleteCredential(credential.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.getCredential(credential.getSecuredUuid()));
    }

    @Test
    void testRemoveCredential_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.deleteCredential(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testEnableCredential() throws NotFoundException {
        credentialService.enableCredential(credential.getSecuredUuid());
        Assertions.assertTrue(credentialService.getCredential(credential.getSecuredUuid()).getEnabled());
    }

    @Test
    void testEnableCredential_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.enableCredential(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableCredential() throws NotFoundException {
        credentialService.disableCredential(credential.getSecuredUuid());
        Assertions.assertFalse(credentialService.getCredential(credential.getSecuredUuid()).getEnabled());
    }

    @Test
    void testDisableCredential_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.disableCredential(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() throws NotFoundException {
        credentialService.bulkDeleteCredential(List.of(credential.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> credentialService.getCredential(credential.getSecuredUuid()));
    }

    @Test
    void testLoadFullData_attributes() throws NotFoundException {
        CredentialAttributeContentData dto = new CredentialAttributeContentData();
        CredentialAttributeContentV2 nameAndUuidMap = new CredentialAttributeContentV2();
        dto.setUuid(credential.getUuid().toString());
        dto.setName(credential.getName());
        nameAndUuidMap.setReference(credential.getUuid().toString());
        nameAndUuidMap.setData(dto);


        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.randomUUID(), "testCredentialAttribute", AttributeContentType.CREDENTIAL,List.of(nameAndUuidMap)));

        List<BaseAttribute> attrs = AttributeDefinitionUtils.clientAttributeConverter(requestAttributes);
        DataAttributeV2 dataAttributeV2 = (DataAttributeV2) attrs.getFirst();
        dataAttributeV2.setType(AttributeType.DATA);
        dataAttributeV2.setContentType(AttributeContentType.CREDENTIAL);


        credentialInternalService.loadFullCredentialData(attrs.stream().map(DataAttribute.class::cast).toList());

        Assertions.assertInstanceOf(CredentialAttributeContentData.class, dataAttributeV2.getContent().getFirst().getData());

        CredentialAttributeContentData credentialDto = ((CredentialAttributeContentV2) dataAttributeV2.getContent().getFirst()).getData();
        Assertions.assertEquals(credential.getUuid().toString(), credentialDto.getUuid());
        Assertions.assertEquals(credential.getName(), credentialDto.getName());
    }

    @Test
    void testLoadFullData_attributesNotFound() {
        CredentialAttributeContentData dto = new CredentialAttributeContentData();
        CredentialAttributeContentV2 nameAndUuidMap = new CredentialAttributeContentV2();
        dto.setUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        dto.setName("wrong-name");
        nameAndUuidMap.setReference("wrong-name");
        nameAndUuidMap.setData(dto);

        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.randomUUID(), "testCredentialAttribute", AttributeContentType.CREDENTIAL, List.of(nameAndUuidMap)));

        List<BaseAttribute> attrs = AttributeDefinitionUtils.clientAttributeConverter(requestAttributes);
        DataAttributeV2 dataAttributeV2 = (DataAttributeV2) attrs.getFirst();

        dataAttributeV2.setType(AttributeType.DATA);
        dataAttributeV2.setContentType(AttributeContentType.CREDENTIAL);

        Assertions.assertThrows(NotFoundException.class, () -> credentialInternalService.loadFullCredentialData(attrs.stream().map(DataAttribute.class::cast).toList()));
    }


    @Test
    void testLoadFullData_attributesNonCredential() {
        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.randomUUID(), "dummyAttributes", AttributeContentType.CREDENTIAL, null));
        Assertions.assertDoesNotThrow(() -> credentialInternalService.loadFullCredentialData(AttributeDefinitionUtils.clientAttributeConverter(requestAttributes).stream().map(DataAttribute.class::cast).toList())); // this should not throw exception
    }

    @Test
    void testLoadFullData_callback() throws NotFoundException {
        String credentialBodyKey = "testCredential";

        CredentialAttributeContentData dto = new CredentialAttributeContentData();
        CredentialAttributeContentV2 nameAndUuidMap = new CredentialAttributeContentV2();
        dto.setUuid(credential.getUuid().toString());
        dto.setName(credential.getName());
        nameAndUuidMap.setReference(credential.getUuid().toString());
        nameAndUuidMap.setData(dto);

        AttributeCallbackMapping mapping = new AttributeCallbackMapping(
                "from",
                AttributeType.DATA,
                AttributeContentType.CREDENTIAL,
                credentialBodyKey,
                Collections.singleton(AttributeValueTarget.BODY));
        ArrayList<CredentialAttributeContentV2> cont = new ArrayList<>();
        cont.add(nameAndUuidMap);
        HashMap<String, Serializable> requestBodyMap = new HashMap<>();
        requestBodyMap.put(credentialBodyKey, cont);

        AttributeCallback callback = new AttributeCallback();
        callback.setMappings(Set.of(mapping));

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        requestAttributeCallback.setBody(requestBodyMap);

        credentialInternalService.loadFullCredentialData(callback, requestAttributeCallback);

        Assertions.assertTrue(requestAttributeCallback.getBody().get(credentialBodyKey) instanceof CredentialAttributeContentData);

        CredentialAttributeContentData credentialDto = (CredentialAttributeContentData) requestAttributeCallback.getBody().get(credentialBodyKey);
        Assertions.assertEquals(credential.getUuid().toString(), credentialDto.getUuid());
        Assertions.assertEquals(credential.getName(), credentialDto.getName());
    }

    @Test
    void testLoadFullData_callbackValidation() {
        String credentialBodyKey = "testCredential";

        CredentialAttributeContentData dto = new CredentialAttributeContentData();
        CredentialAttributeContentV2 nameAndUuidMap = new CredentialAttributeContentV2();
        dto.setUuid("abfbc322-29e1-11ed-a261-0242ac120002");
        dto.setName("wrong-name");
        nameAndUuidMap.setReference("wrong-name");
        nameAndUuidMap.setData(dto);

        AttributeCallbackMapping mapping = new AttributeCallbackMapping(
                "from",
                AttributeType.DATA,
                AttributeContentType.CREDENTIAL,
                credentialBodyKey,
                Collections.singleton(AttributeValueTarget.BODY));

        HashMap<String, Serializable> requestBodyMap = new HashMap<>();

        AttributeCallback callback = new AttributeCallback();
        callback.setMappings(Set.of(mapping));

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        requestAttributeCallback.setBody(requestBodyMap);

        Assertions.assertThrows(ValidationException.class, () -> credentialInternalService.loadFullCredentialData(callback, requestAttributeCallback));
    }

    @Test
    void testLoadFullData_callbackValidationFailWrongValue() {
        String credentialBodyKey = "testCredential";

        AttributeCallbackMapping mapping = new AttributeCallbackMapping(
                "from",
                AttributeType.DATA,
                AttributeContentType.CREDENTIAL,
                credentialBodyKey,
                Collections.singleton(AttributeValueTarget.BODY));

        HashMap<String, Serializable> requestBodyMap = new HashMap<>();
        requestBodyMap.put(credentialBodyKey, "wrong-value");

        AttributeCallback callback = new AttributeCallback();
        callback.setMappings(Set.of(mapping));

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        requestAttributeCallback.setBody(requestBodyMap);

        Assertions.assertThrows(ValidationException.class, () -> credentialInternalService.loadFullCredentialData(callback, requestAttributeCallback));
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = credentialInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = credentialInternalService.getResourceObjectInternal(credential.getUuid());
        Assertions.assertEquals(credential.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(credential.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = credentialInternalService.getResourceObjectExternal(credential.getSecuredUuid());
        Assertions.assertEquals(credential.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(credential.getName(), nameAndUuidDto.getName());
    }
}
