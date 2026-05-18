package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.czertainly.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.DataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.czertainly.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceCertificateContentData;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.other.ResourceDto;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.other.ResourceEventDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.entity.AttributeDefinition;
import com.czertainly.core.dao.entity.AttributeRelation;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.repository.AttributeDefinitionRepository;
import com.czertainly.core.dao.repository.AttributeRelationRepository;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.opa.dto.OpaRequestedResource;
import com.czertainly.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.Serializable;
import java.util.*;
import java.util.List;
import java.util.Map;
import java.util.UUID;

class ResourceServiceTest extends BaseSpringBootTest {

    private static final int AUTH_SERVICE_MOCK_PORT = 10001;
    private static final String CERTIFICATE_UUID = "c1cfe60f-2556-461f-9a64-9dd8e92158cf";
    private static final String ATTRIBUTE_UUID = "f1982dfe-2523-45cf-9bfe-034ff1659369";

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:" + AUTH_SERVICE_MOCK_PORT);
    }

    @Autowired
    private ResourceService resourceService;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;
    @Autowired
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

    @Autowired
    private CertificateService certificateService;

    private WireMockServer mockServer;

    private Certificate certificate;

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(AUTH_SERVICE_MOCK_PORT);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        WireMock.stubFor(
                WireMock.get(WireMock.urlPathEqualTo("/auth/users"))
                        .willReturn(WireMock.aResponse()
                                .withHeader("Content-Type", "application/json")
                                .withBody( // UserWithPaginationDto
                                        """
                                        {
                                            "currentPage": 1,
                                            "pageSize": 2,
                                            "totalPages": 1,
                                            "totalCount": 2,
                                            "hasPrevious": 0,
                                            "hasNext": 0,
                                            "data": [
                                                {
                                                    "uuid": "mock-user-uuid",
                                                    "username": "mockUser",
                                                    "groups": [],
                                                    "enabled": true,
                                                    "systemUser": false
                                                },
                                                {
                                                    "uuid": "mock-user-uuid-2",
                                                    "username": "mockUser2",
                                                    "groups": [],
                                                    "enabled": true,
                                                    "systemUser": false
                                                }
                                            ]
                                        }
                                        """
                                )
                        )
        );

        certificate = createCertificate(UUID.fromString(CERTIFICATE_UUID), "123456", "123456789", "testCertificate");

        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(ATTRIBUTE_UUID);
        attribute.setName("testAttribute");
        attribute.setDescription("description");
        attribute.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties attributeProperties = new CustomAttributeProperties();
        attributeProperties.setReadOnly(true);
        attributeProperties.setRequired(true);
        attribute.setProperties(attributeProperties);

        AttributeDefinition attributeDefinition = new AttributeDefinition();
        attributeDefinition.setUuid(UUID.fromString(ATTRIBUTE_UUID));
        attributeDefinition.setName("testAttribute");
        attributeDefinition.setAttributeUuid(UUID.fromString(ATTRIBUTE_UUID));
        attributeDefinition.setContentType(AttributeContentType.STRING);
        attributeDefinition.setLabel("testAttributeLabel");
        attributeDefinition.setType(AttributeType.CUSTOM);
        attributeDefinition.setDefinition(attribute);
        attributeDefinition.setEnabled(true);
        attributeDefinition.setVersion(3);
        attributeDefinitionRepository.save(attributeDefinition);

        AttributeRelation attributeRelation = new AttributeRelation();
        attributeRelation.setResource(Resource.CERTIFICATE);
        attributeRelation.setAttributeDefinitionUuid(attributeDefinition.getUuid());
        attributeRelationRepository.save(attributeRelation);
    }

    private Certificate createCertificate(UUID uuid, String content, String serialNumber, String subjectDn) {
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(content);
        certificateContent = certificateContentRepository.save(certificateContent);

        Certificate newCertificate = new Certificate();
        newCertificate.setSubjectDn(subjectDn);
        newCertificate.setIssuerDn("testCertificate");
        newCertificate.setSerialNumber(serialNumber);
        newCertificate.setState(CertificateState.ISSUED);
        newCertificate.setValidationStatus(CertificateValidationStatus.VALID);
        newCertificate.setCertificateContent(certificateContent);
        newCertificate.setCertificateContentId(certificateContent.getId());
        newCertificate.setUuid(uuid);
        return certificateRepository.save(newCertificate);
    }

    @Test
    void testListResources() {
        // Call the method to test
        List<ResourceDto> resources = resourceService.listResources();

        // Assert the expected results
        Assertions.assertNotNull(resources);
        Assertions.assertFalse(resources.isEmpty(), "Resource list should not be empty");
        Assertions.assertTrue(resources.stream().anyMatch(
                resource -> resource.getResource().getCode().equals(Resource.Codes.CERTIFICATE)),
                "Resource list should contain CERTIFICATE resource");
    }

    @Test
    void testGetResourceObjects() {
        List<Resource> resources = List.of(
                Resource.ACME_PROFILE,
                Resource.AUTHORITY,
                Resource.ATTRIBUTE,
                Resource.COMPLIANCE_PROFILE,
                Resource.CONNECTOR,
                Resource.CERTIFICATE,
                Resource.CREDENTIAL,
                Resource.ENTITY,
                Resource.GROUP,
                Resource.LOCATION,
                Resource.RA_PROFILE,
                Resource.SCEP_PROFILE,
                Resource.TOKEN_PROFILE,
                Resource.TOKEN,
                Resource.USER,
                Resource.CMP_PROFILE
        );

        for (Resource resource : resources) {
            // Call the method to test and check that it does not throw an exception
            Assertions.assertDoesNotThrow(() -> resourceService.getResourceObjects(resource, null, null), "Should not throw exception for resource: " + resource);
        }

        // Throw NotFoundException for unsupported resource
        Resource unsupportedResource = Resource.ROLE;
        Assertions.assertThrows(NotSupportedException.class, () -> resourceService.getResourceObjects(unsupportedResource, null, null), "Should throw NotSupportedException for unsupported resource: " + unsupportedResource);
        Assertions.assertThrows(NotSupportedException.class, () -> resourceService.getResourceObjects(Resource.RULE, null, null), "Should throw NotSupportedException for unsupported resource: " + Resource.RULE);
    }

    @Test
    void testUpdateAttributeContentForObject() throws NotFoundException, AttributeException {
        SecuredUUID certificateUuid = SecuredUUID.fromString(CERTIFICATE_UUID);
        UUID attributeUuid = UUID.fromString(ATTRIBUTE_UUID);
        List<BaseAttributeContentV3<?>> request = List.of(new StringAttributeContentV3("test3"));
        List<ResponseAttribute> responseAttributes = resourceService.updateAttributeContentForObject(
                Resource.CERTIFICATE,
                certificateUuid,
                attributeUuid,
                request
        );

        Assertions.assertEquals("test3", ((ResponseAttributeV3) responseAttributes.getFirst()).getContent().getFirst().getData());

        List<BaseAttributeContentV2<?>> requestV2 = List.of(new StringAttributeContentV2("test2"));
        responseAttributes = resourceService.updateAttributeContentForObject(
                Resource.CERTIFICATE,
                certificateUuid,
                attributeUuid,
                requestV2
        );

        Assertions.assertEquals("test2", ((ResponseAttributeV3) responseAttributes.getFirst()).getContent().getFirst().getData());

        // Should throw NotSupported
        Assertions.assertThrows(NotSupportedException.class, () -> resourceService.updateAttributeContentForObject(
                Resource.ATTRIBUTE,
                certificateUuid,
                attributeUuid,
                request
        ));

        Assertions.assertThrows(NotSupportedException.class, () -> resourceService.updateAttributeContentForObject(
                Resource.RULE,
                certificateUuid,
                attributeUuid,
                request
        ));
    }

    @Test
    void testListResourceRuleFilterFields() throws NotFoundException {
        // Resource without filter fields and attributes should return empty list
        List<SearchFieldDataByGroupDto> filterFields = resourceService.listResourceRuleFilterFields(Resource.USER, false);
        Assertions.assertNotNull(filterFields);
        Assertions.assertTrue(filterFields.isEmpty(), "Filter fields list should be empty for resource: " + Resource.USER);

        // Resource == CERTIFICATE should return non-empty list
        filterFields = resourceService.listResourceRuleFilterFields(Resource.CERTIFICATE, false);
        Assertions.assertNotNull(filterFields);
        Assertions.assertFalse(filterFields.isEmpty(), "Filter fields list should not be empty for resource: " + Resource.CERTIFICATE);
    }

    @Test
    void testListResourceEvents() {
        // Call the method to test
        List<ResourceEventDto> events = resourceService.listResourceEvents(Resource.CERTIFICATE);

        // Assert the expected results
        Assertions.assertNotNull(events);
        Assertions.assertFalse(events.isEmpty(), "Resource event list should not be empty");
        Assertions.assertTrue(events.stream().anyMatch(
                event -> event.getEvent().getCode().equals(ResourceEvent.CERTIFICATE_DISCOVERED.getCode())),
                "Resource event list should contain CERTIFICATE_DISCOVERED event");
    }

    @Test
    void testListAllResourceEvents() {
        // Call the method to test
        Map<ResourceEvent, List<ResourceEventDto>> events = resourceService.listAllResourceEvents();

        // Assert the expected results
        Assertions.assertNotNull(events);
        Assertions.assertFalse(events.isEmpty(), "Resource event map should not be empty");
        Assertions.assertTrue(events.keySet().stream().anyMatch(
                event -> event.getCode().equals(ResourceEvent.CERTIFICATE_DISCOVERED.getCode())),
                "Resource event map should contain CERTIFICATE_DISCOVERED event");
    }

    @Test
    @Transactional
    void testLoadResourceObjectContentDataFromDataAttributes() throws NotFoundException, AttributeException, ConnectorException {
        DataAttributeV3 nonResourceAttribute = new DataAttributeV3();
        nonResourceAttribute.setName("name");
        nonResourceAttribute.setContentType(AttributeContentType.DATE);

        Certificate certificate1 = createCertificate(UUID.randomUUID(), "1234567", "1234567890", "testCertificate1");
        
        DataAttributeV3 resourceAttribute = new DataAttributeV3();
        resourceAttribute.setContentType(AttributeContentType.RESOURCE);
        resourceAttribute.setName("resource");
        ResourceCertificateContentData data = new ResourceCertificateContentData();
        data.setUuid(certificate.getUuid().toString());
        ResourceCertificateContentData data2 = new ResourceCertificateContentData();
        data2.setUuid(certificate1.getUuid().toString());
        resourceAttribute.setContent(List.of(new ResourceObjectContent("ref", data), new ResourceObjectContent("ref2", data2)));
        DataAttributeProperties properties = new DataAttributeProperties();
        resourceAttribute.setProperties(properties);
        properties.setResource(AttributeResource.CERTIFICATE);

        resourceService.loadResourceObjectContentData(List.of(nonResourceAttribute, resourceAttribute));
        Assertions.assertNull(nonResourceAttribute.getContent());
        Assertions.assertEquals(2, resourceAttribute.getContent().size());
        ResourceCertificateContentData dataWithResource = (ResourceCertificateContentData) resourceAttribute.getContent().getFirst().getData();
        Assertions.assertEquals(certificate.getContentData(), dataWithResource.getContent());
        Assertions.assertEquals(AttributeResource.CERTIFICATE, dataWithResource.getResource());
        Assertions.assertEquals(certificate.getCommonName(), dataWithResource.getName());
        Assertions.assertEquals(certificate.getUuid().toString(), dataWithResource.getUuid());

        dataWithResource = (ResourceCertificateContentData) resourceAttribute.getContent().get(1).getData();
        Assertions.assertEquals(certificate1.getContentData(), dataWithResource.getContent());
        Assertions.assertEquals(AttributeResource.CERTIFICATE, dataWithResource.getResource());
        Assertions.assertEquals(certificate1.getCommonName(), dataWithResource.getName());
        Assertions.assertEquals(certificate1.getUuid().toString(), dataWithResource.getUuid());
    }

    @Test
    void testLoadResourceObjectContentDataToBody() throws NotFoundException, AttributeException, ConnectorException {
        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("auth");
        authorityInstanceReferenceRepository.save(authorityInstance);

        createAttributes(authorityInstance);

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        Map<String, AttributeResource> authorityMap = Map.of("to", AttributeResource.AUTHORITY);
        resourceService.loadResourceObjectContentData(null, requestAttributeCallback, authorityMap);
        Assertions.assertNull(requestAttributeCallback.getBody());
        AttributeCallback attributeCallback = new AttributeCallback();
        resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap);
        Assertions.assertNull(requestAttributeCallback.getBody());
        AttributeCallbackMapping stringMapping = new AttributeCallbackMapping();
        stringMapping.setAttributeContentType(AttributeContentType.STRING);
        AttributeCallbackMapping resourceMapping = new AttributeCallbackMapping();
        resourceMapping.setAttributeContentType(AttributeContentType.RESOURCE);
        resourceMapping.setTo("to");
        resourceMapping.setTargets(Set.of(AttributeValueTarget.PATH_VARIABLE, AttributeValueTarget.BODY));
        attributeCallback.setMappings(Set.of(stringMapping, resourceMapping));

        Map<String, Serializable> body = new HashMap<>();

        body.put(resourceMapping.getTo(), (Serializable) Map.of("uuid", authorityInstance.getUuid().toString(), "name", authorityInstance.getName()));
        requestAttributeCallback.setBody(body);
        resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap);
        assertCorrectBodyData(requestAttributeCallback, resourceMapping, authorityInstance);
        Assertions.assertEquals("name", ((ResourceSimpleContentData) requestAttributeCallback.getBody().get(resourceMapping.getTo())).getAttributes().getFirst().getName());


        body.put(resourceMapping.getTo(), (Serializable) List.of(Map.of("uuid", authorityInstance.getUuid().toString(), "name", authorityInstance.getName())));
        requestAttributeCallback.setBody(body);
        resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap);
        assertCorrectBodyData(requestAttributeCallback, resourceMapping, authorityInstance);
        Assertions.assertEquals("name", ((ResourceSimpleContentData) requestAttributeCallback.getBody().get(resourceMapping.getTo())).getAttributes().getFirst().getName());


        body.put(resourceMapping.getTo(), (Serializable) Map.of("name", authorityInstance.getName()));
        requestAttributeCallback.setBody(body);
        Assertions.assertThrows(ValidationException.class, () -> resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap));

        body.put(resourceMapping.getTo(), (Serializable) List.of(Map.of("name", authorityInstance.getName())));
        requestAttributeCallback.setBody(body);
        Assertions.assertThrows(ValidationException.class, () -> resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap));

        body.put(resourceMapping.getTo(), 1);
        requestAttributeCallback.setBody(body);
        Assertions.assertThrows(ValidationException.class, () -> resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap));

        body.put(resourceMapping.getTo(), "notUuid");
        requestAttributeCallback.setBody(body);
        Assertions.assertThrows(ValidationException.class, () -> resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap));

        body.put(resourceMapping.getTo(), authorityInstance.getUuid().toString());
        requestAttributeCallback.setBody(body);
        resourceService.loadResourceObjectContentData(attributeCallback, requestAttributeCallback, authorityMap);
        assertCorrectBodyData(requestAttributeCallback, resourceMapping, authorityInstance);

    }

    @Test
    void  testGetResourceWithAuthorization() throws NotFoundException {
        forbidGetResourceWithAuthorization();
        List<Resource> allowedResources = List.of(
                Resource.ACME_PROFILE,
                Resource.AUTHORITY,
                Resource.ATTRIBUTE,
                Resource.COMPLIANCE_PROFILE,
                Resource.CONNECTOR,
                Resource.CERTIFICATE,
                Resource.CREDENTIAL,
                Resource.ENTITY,
                Resource.GROUP,
                Resource.LOCATION,
                Resource.SCEP_PROFILE,
                Resource.TOKEN_PROFILE,
                Resource.TOKEN,
                Resource.CMP_PROFILE
        );

        List<Resource> notAllowedResources = List.of(
                Resource.RA_PROFILE,
                Resource.SECRET
        );

        UUID objectUuid = UUID.randomUUID();
        for (Resource resource : allowedResources) {
            Assertions.assertThrows(NotFoundException.class, () -> resourceService.getResourceObject(resource, objectUuid));
            Assertions.assertThrows(NotFoundException.class, () -> resourceService.getResourceObjectInternal(resource, objectUuid));
        }

        for (Resource resource : notAllowedResources) {
            Assertions.assertThrows(AuthorizationDeniedException.class, () -> resourceService.getResourceObject(resource, objectUuid));
            Assertions.assertThrows(NotFoundException.class, () -> resourceService.getResourceObjectInternal(resource, objectUuid));
        }
    }

    void forbidGetResourceWithAuthorization() {
        OpaResourceAccessResult resourceAccessNotAllowed = new OpaResourceAccessResult(false, List.of());

        Mockito.when(
                opaClient.checkResourceAccess(Mockito.any(),
                        Mockito.argThat(req -> isRequestForResourceAction(req, Resource.RA_PROFILE)), Mockito.any(), Mockito.any())
        ).thenReturn(resourceAccessNotAllowed);

        Mockito.when(
                opaClient.checkResourceAccess(Mockito.any(),  Mockito.argThat(req ->
                        isRequestForResourceAction(req, Resource.SECRET)
                ), Mockito.any(), Mockito.any())
        ).thenReturn(resourceAccessNotAllowed);

    }

    private static boolean isRequestForResourceAction(OpaRequestedResource requestedResource, Resource resource) {
        return requestedResource != null && requestedResource.getProperties() != null &&
                (requestedResource.getProperties().containsKey("name") && requestedResource.getProperties().get("name").equals(resource.getCode())) &&
                (requestedResource.getProperties().containsKey("action") && requestedResource.getProperties().get("action").equals(ResourceAction.DETAIL.getCode()));
    }


    private static void assertCorrectBodyData(RequestAttributeCallback requestAttributeCallback, AttributeCallbackMapping resourceMapping, AuthorityInstanceReference authorityInstance) {
        ResourceSimpleContentData data = (ResourceSimpleContentData) requestAttributeCallback.getBody().get(resourceMapping.getTo());
        Assertions.assertEquals(authorityInstance.getUuid().toString(), data.getUuid());
        List<ResponseAttribute> attributes = data.getAttributes();
        Assertions.assertEquals(1, attributes.size());
        List<StringAttributeContentV3> attributeContent = attributes.getFirst().getContent();
        Assertions.assertEquals("data", attributeContent.getFirst().getData());
    }

    private void createAttributes(AuthorityInstanceReference authorityInstance) {
        AttributeDefinition definition = new AttributeDefinition();
        definition.setType(AttributeType.DATA);
        definition.setName("name");
        definition.setLabel("label");
        definition.setVersion(3);
        DataAttributeV3 dataAttributeV3 = new DataAttributeV3();
        dataAttributeV3.setContentType(AttributeContentType.STRING);
        definition.setDefinition(dataAttributeV3);
        definition.setAttributeUuid(UUID.randomUUID());
        definition.setContentType(AttributeContentType.STRING);
        attributeDefinitionRepository.save(definition);
        AttributeContentItem attributeContentItem = new AttributeContentItem();
        attributeContentItem.setAttributeDefinitionUuid(definition.getUuid());
        attributeContentItem.setJson(new StringAttributeContentV3("data"));
        attributeContentItemRepository.save(attributeContentItem);
        AttributeContent2Object attributeContent2Object = new AttributeContent2Object();
        attributeContent2Object.setAttributeContentItemUuid(attributeContentItem.getUuid());
        attributeContent2Object.setObjectUuid(authorityInstance.getUuid());
        attributeContent2Object.setObjectType(Resource.AUTHORITY);
        attributeContent2Object.setOrder(1);
        attributeContent2ObjectRepository.save(attributeContent2Object);
    }
}
