package com.czertainly.core.attribute;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.*;
import com.czertainly.api.model.client.metadata.MetadataResponseDto;
import com.czertainly.api.model.common.attribute.common.*;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.czertainly.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.czertainly.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.czertainly.api.model.common.attribute.v2.*;
import com.czertainly.api.model.common.attribute.v2.content.*;
import com.czertainly.api.model.common.attribute.common.content.data.CodeBlockAttributeContentData;
import com.czertainly.api.model.common.attribute.common.content.data.ProgrammingLanguageEnum;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.DataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.MetadataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.*;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityResourceFilter;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

class AttributeEngineTest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;
    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;
    @Autowired
    private AttributeRelationRepository attributeRelationRepository;
    @Autowired
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;
    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;

    private Connector connectorAuthority;
    private Connector connectorDiscovery;
    private Certificate certificate;
    private UUID authorityDiscoveryUuid;
    private UUID networkDiscoveryUuid;

    CustomAttributeV3 orderNoCustomAttribute;
    CustomAttributeV3 departmentCustomAttribute;
    CustomAttributeV3 expirationDateCustomAttribute;
    private MetadataAttributeV3 networkDiscoveryMeta;

    @BeforeEach
    void setUp() throws AttributeException, NotFoundException {
        connectorAuthority = new Connector();
        connectorAuthority.setName("EJBCAAuthorityConnector");
        connectorAuthority.setUrl("http://localhost:8080");
        connectorAuthority.setVersion(ConnectorVersion.V1);
        connectorAuthority.setStatus(ConnectorStatus.CONNECTED);
        connectorAuthority = connectorRepository.save(connectorAuthority);

        connectorDiscovery = new Connector();
        connectorDiscovery.setName("NetworkDiscoveryConnector");
        connectorDiscovery.setUrl("http://localhost:8081");
        connectorDiscovery.setVersion(ConnectorVersion.V1);
        connectorDiscovery.setStatus(ConnectorStatus.CONNECTED);
        connectorDiscovery = connectorRepository.save(connectorDiscovery);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("testAuthorityInstance1");
        authorityInstance.setConnector(connectorAuthority);
        authorityInstance.setConnectorUuid(connectorAuthority.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfile = raProfileRepository.save(raProfile);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCercertificatetificate");
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setRaProfile(raProfile);
        certificate = certificateRepository.save(certificate);

        // Ensure OwnerAssociation is created and associated
        OwnerAssociation ownerAssociation = new OwnerAssociation();
        ownerAssociation.setOwnerUuid(UUID.randomUUID()); // Set a proper UUID
        ownerAssociation.setOwnerUsername("ownerName");
        ownerAssociation.setResource(Resource.CERTIFICATE);
        ownerAssociation.setObjectUuid(certificate.getUuid());
        ownerAssociation.setCertificate(certificate);
        ownerAssociation = ownerAssociationRepository.saveAndFlush(ownerAssociation);

        certificate.setOwner(ownerAssociation);
        certificateRepository.save(certificate);

        networkDiscoveryUuid = UUID.randomUUID();
        authorityDiscoveryUuid = UUID.randomUUID();

        loadMetadata();
        loadCustomAttributesData();
    }

    @Test
    void testUpdateValidateResourceAttribute() {
        DataAttributeV3 resourceAttribute = new DataAttributeV3();
        resourceAttribute.setContentType(AttributeContentType.RESOURCE);
        resourceAttribute.setName("resource");
        resourceAttribute.setUuid(UUID.randomUUID().toString());
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("l");
        resourceAttribute.setProperties(properties);
        List<DataAttributeV3> attributes = List.of(resourceAttribute);
        UUID connectorUuid = connectorAuthority.getUuid();
        Assertions.assertThrows(AttributeException.class, () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, attributes));
        properties.setResource(AttributeResource.AUTHORITY);
        Assertions.assertThrows(AttributeException.class, () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, attributes));
        resourceAttribute.setAttributeCallback(new AttributeCallback());
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, attributes));
    }


    @Test
    void testMetaContents() {
        var mappedMetadata = attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).build());
        Assertions.assertEquals(3, mappedMetadata.size());
    }

    @Test
    void testMetadataContentReplacement() throws AttributeException {

        networkDiscoveryMeta.setContent(List.of(new StringAttributeContentV3("localhost:1443"), new StringAttributeContentV3("localhost:2443"), new StringAttributeContentV3("localhost:3443")));

        attributeEngine.updateMetadataAttribute(networkDiscoveryMeta, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).source(Resource.DISCOVERY, networkDiscoveryUuid).build());
        var mappedMetadata = attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).build());
        Optional<MetadataResponseDto> metadataResponseDto = mappedMetadata.stream().filter(m -> m.getConnectorUuid().equals(connectorDiscovery.getUuid().toString())).findFirst();
        Assertions.assertTrue(metadataResponseDto.isPresent());
        Assertions.assertEquals(4, metadataResponseDto.get().getItems().getFirst().getContent().size());

        networkDiscoveryMeta.getProperties().setOverwrite(true);
        List<BaseAttributeContentV3<?>> contentV3s = new ArrayList<>();
        contentV3s.add(new StringAttributeContentV3("TEST", "TEST"));
        networkDiscoveryMeta.setContent(contentV3s);
        attributeEngine.updateMetadataAttribute(networkDiscoveryMeta, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).source(Resource.DISCOVERY, networkDiscoveryUuid).build());
        mappedMetadata = attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).build());
        metadataResponseDto = mappedMetadata.stream().filter(m -> m.getConnectorUuid().equals(connectorDiscovery.getUuid().toString())).findFirst();
        Assertions.assertTrue(metadataResponseDto.isPresent());
        Assertions.assertEquals(3, mappedMetadata.size());
        Assertions.assertEquals(1, metadataResponseDto.get().getItems().getFirst().getContent().size());
        Assertions.assertEquals("TEST", metadataResponseDto.get().getItems().getFirst().getContent().getFirst().getReference());
    }

    @Test
    void testAttributeContentValidation() {
        RequestAttributeV3 departmentAttributeDto = new RequestAttributeV3();
        departmentAttributeDto.setUuid(UUID.fromString(departmentCustomAttribute.getUuid()));
        departmentAttributeDto.setName(departmentCustomAttribute.getName());
        departmentAttributeDto.setContent(List.of(new StringAttributeContentV3("Sales")));

        RequestAttributeV3 expirationDateAttributeDto = new RequestAttributeV3();
        expirationDateAttributeDto.setUuid(UUID.fromString(expirationDateCustomAttribute.getUuid()));
        expirationDateAttributeDto.setName(expirationDateCustomAttribute.getName());
        expirationDateAttributeDto.setContent(List.of(new DateAttributeContentV3(LocalDate.now())));

        List<RequestAttribute> departmentAttributeDtoList = List.of(departmentAttributeDto);
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CONNECTOR, departmentAttributeDtoList), "Custom attribute content should not be updated to resource not assigned");
        List<RequestAttribute> departmentExpirationDateList = List.of(departmentAttributeDto, expirationDateAttributeDto);
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, departmentExpirationDateList), "Read-only attribute content should not be able to be changed");

        expirationDateAttributeDto.setContent(List.of(new IntegerAttributeContentV3(100)));
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, departmentExpirationDateList), "Mismatch between content types");

        expirationDateAttributeDto.setContent(List.of(new DateAttributeContentV3(LocalDate.EPOCH)));
        List<RequestAttribute> expirationDateAttributeDtoList = List.of(expirationDateAttributeDto);
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, expirationDateAttributeDtoList), "Missing content for required custom attribute");

        // the following should not throw any exception, we cannot update read-only attributes
        UUID certificateUuid = certificate.getUuid();
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificateUuid, departmentExpirationDateList), "Read-only attribute content should not be able to be changed");
    }

    @Test
    void testExtensibleListAttributeContentValidation() throws AttributeException {
        CustomAttributeV3 extensibleListAttribute = new CustomAttributeV3();
        extensibleListAttribute.setUuid(UUID.randomUUID().toString());
        extensibleListAttribute.setName("extensibleListAttribute");
        extensibleListAttribute.setType(AttributeType.CUSTOM);
        extensibleListAttribute.setContentType(AttributeContentType.STRING);

        CustomAttributeProperties customProps = new CustomAttributeProperties();
        customProps.setLabel("Strict List Attribute");
        customProps.setList(false);
        customProps.setExtensibleList(true);
        extensibleListAttribute.setProperties(customProps);

        Assertions.assertThrows(AttributeException.class, () -> attributeEngine.updateCustomAttributeDefinition(extensibleListAttribute, List.of(Resource.CERTIFICATE)), "Extensible list attribute should be a list attribute");

        customProps.setList(true);
        customProps.setExtensibleList(false);
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateCustomAttributeDefinition(extensibleListAttribute, List.of(Resource.CERTIFICATE)), "Not extensible list attribute does not need to have content");

        extensibleListAttribute.setContent(List.of(new StringAttributeContentV3("data1"), new StringAttributeContentV3("data2")));
        attributeEngine.updateCustomAttributeDefinition(extensibleListAttribute, List.of(Resource.CERTIFICATE));

        RequestAttributeV3 strictListAttributeDto = new RequestAttributeV3();
        UUID definitionUuid = UUID.fromString(extensibleListAttribute.getUuid());
        strictListAttributeDto.setUuid(definitionUuid);
        String attributeName = extensibleListAttribute.getName();
        strictListAttributeDto.setName(attributeName);
        List<BaseAttributeContentV3<?>> invalidOption = List.of(new StringAttributeContentV3("InvalidOption"));
        strictListAttributeDto.setContent(invalidOption);

        UUID certificateUuid = certificate.getUuid();
        UUID finalDefinitionUuid2 = definitionUuid;
        Assertions.assertThrows(AttributeException.class, () -> attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, finalDefinitionUuid2, attributeName, invalidOption), "Content not in predefined options should not be accepted for not extensible list attribute");

        List<AttributeContent> validContent = List.of(new StringAttributeContentV3("data1"));
        UUID finalDefinitionUuid = definitionUuid;
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, finalDefinitionUuid, attributeName, validContent), "Valid content should be accepted for not extensible list attribute");

        List<AttributeContent> validContentV2 = List.of(new StringAttributeContentV2("data1"));
        UUID finalDefinitionUuid1 = definitionUuid;
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, finalDefinitionUuid1, attributeName, validContentV2), "Valid content in v2 should be accepted for not extensible list attribute");

        extensibleListAttribute.setContentType(AttributeContentType.CODEBLOCK);
        CodeBlockAttributeContentV3 attributeContent = new CodeBlockAttributeContentV3();
        attributeContent.setContentType(AttributeContentType.CODEBLOCK);
        attributeContent.setData(new CodeBlockAttributeContentData(ProgrammingLanguageEnum.PYTHON, "abc"));
        extensibleListAttribute.setContent(List.of(attributeContent));
        extensibleListAttribute.setUuid(UUID.randomUUID().toString());
        attributeEngine.updateCustomAttributeDefinition(extensibleListAttribute, List.of(Resource.CERTIFICATE));

        definitionUuid = UUID.fromString(extensibleListAttribute.getUuid());
        strictListAttributeDto.setUuid(definitionUuid);
        strictListAttributeDto.setContent(List.of(attributeContent));
        UUID finalDefinitionUuid3 = definitionUuid;
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, finalDefinitionUuid3, attributeName, List.of(attributeContent)), "Valid code block content should be accepted for not extensible list attribute");

        customProps.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        attributeEngine.updateCustomAttributeDefinition(extensibleListAttribute, List.of(Resource.CERTIFICATE));
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, finalDefinitionUuid3, attributeName, List.of(attributeContent)), "Valid code block content should be accepted for not extensible list attribute with encrypted protection level");

        DataAttributeV2 dataAttributeV2 = new DataAttributeV2();
        dataAttributeV2.setUuid(UUID.randomUUID().toString());
        dataAttributeV2.setName("dataAttributeV2");
        dataAttributeV2.setContentType(AttributeContentType.STRING);
        dataAttributeV2.setContent(List.of(new StringAttributeContentV2("data")));
        DataAttributeProperties dataProps = new DataAttributeProperties();
        dataProps.setLabel("Data Attribute V2");
        dataProps.setList(true);
        dataProps.setExtensibleList(false);
        dataProps.setReadOnly(false);
        dataAttributeV2.setProperties(dataProps);
        attributeEngine.updateDataAttributeDefinitions(null, null, List.of(dataAttributeV2));
        RequestAttributeV2 requestAttributeV2 = new RequestAttributeV2();
        requestAttributeV2.setUuid(UUID.fromString(dataAttributeV2.getUuid()));
        requestAttributeV2.setName(dataAttributeV2.getName());
        // For this test, BaseAttributeContentV2 is used instead of StringAttributeContentV2 because v2 is missing discriminator, and therefore it will not be deserialized to StringAttributeContentV2 from JSON in request
        BaseAttributeContentV2<String> stringContentV2 = new BaseAttributeContentV2<>();
        stringContentV2.setReference("data");
        stringContentV2.setData("data");
        requestAttributeV2.setContent(List.of(stringContentV2));
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificateUuid).build(), List.of(requestAttributeV2)), "Valid content should be accepted for not extensible list v2 attribute");

        dataProps.setList(false);
        attributeEngine.updateDataAttributeDefinitions(null, null, List.of(dataAttributeV2));
        stringContentV2.setData("data2");
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificateUuid).build(), List.of(requestAttributeV2)), "Valid content should be accepted for not extensible list v2 attribute");

    }

    @Test
    void updateObjectDataAttributesContentAcceptsNullContentForNonRequiredAttribute() throws AttributeException {
        // Regression: a connector legitimately returning content=null for an optional attribute
        // used to NPE deep in createObjectAttributeContent (attributeContentItems.size() on null),
        // surfacing as HTTP 500 with a framework-internal message instead of a clean no-op.
        // validateAttributeContent already accepts null/empty equivalently for non-required
        // attributes; the iteration site must mirror that contract.
        DataAttributeV3 optionalAttribute = new DataAttributeV3();
        optionalAttribute.setUuid(UUID.randomUUID().toString());
        optionalAttribute.setName("optionalNullContentAttribute");
        optionalAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Optional null-content attribute");
        props.setRequired(false);
        optionalAttribute.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(null, null, List.of(optionalAttribute));

        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(optionalAttribute.getUuid()));
        requestAttribute.setName(optionalAttribute.getName());
        requestAttribute.setContent(null);

        UUID certificateUuid = certificate.getUuid();
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificateUuid).build(),
                        List.of(requestAttribute)),
                "null content for a non-required attribute must be a no-op, not an NPE");
    }

    @Test
    void testGetDataAttributesByContent() throws AttributeException {
        DataAttributeV2 dataAttributeV2 = new DataAttributeV2();
        dataAttributeV2.setUuid(UUID.randomUUID().toString());
        dataAttributeV2.setName("name");
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("label");
        dataAttributeV2.setProperties(properties);
        dataAttributeV2.setContent(List.of(new StringAttributeContentV2("data")));
        dataAttributeV2.setContentType(AttributeContentType.STRING);
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(dataAttributeV2));

        DataAttributeV3 dataAttributeV3 = new DataAttributeV3();
        dataAttributeV3.setUuid(UUID.randomUUID().toString());
        dataAttributeV3.setName("name3");
        DataAttributeProperties properties3 = new DataAttributeProperties();
        properties3.setLabel("label3");
        dataAttributeV3.setProperties(properties3);
        dataAttributeV3.setContent(List.of(new StringAttributeContentV3("data3")));
        dataAttributeV3.setContentType(AttributeContentType.STRING);
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(dataAttributeV3));

        RequestAttributeV2 requestAttributeV2 = new RequestAttributeV2();
        requestAttributeV2.setUuid(UUID.fromString(dataAttributeV2.getUuid()));
        requestAttributeV2.setName(dataAttributeV2.getName());
        requestAttributeV2.setContent(List.of(new StringAttributeContentV2("data-request")));

        RequestAttributeV3 requestAttributeV3 = new RequestAttributeV3();
        requestAttributeV3.setUuid(UUID.fromString(dataAttributeV3.getUuid()));
        requestAttributeV3.setName(dataAttributeV3.getName());
        requestAttributeV3.setContent(List.of(new StringAttributeContentV3("data-request3")));

        List<DataAttribute> attributes = attributeEngine.getDataAttributesByContent(connectorAuthority.getUuid(), List.of(requestAttributeV2, requestAttributeV3));
        Assertions.assertEquals(2, attributes.size());
        Assertions.assertEquals(dataAttributeV2.getUuid(), attributes.getFirst().getUuid());
        Assertions.assertEquals(requestAttributeV2.getContent(), attributes.getFirst().getContent());
        Assertions.assertEquals(dataAttributeV3.getUuid(), attributes.getLast().getUuid());
        Assertions.assertEquals(requestAttributeV3.getContent(), attributes.getLast().getContent());

        AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByConnectorUuidAndAttributeUuid(connectorAuthority.getUuid(), UUID.fromString(dataAttributeV2.getUuid())).orElseThrow();
        Assertions.assertEquals(dataAttributeV2.getContent().getFirst().getData(), ((List<AttributeContent>) attributeDefinition.getDefinition().getContent()).getFirst().getData());

        AttributeDefinition attributeDefinition3 = attributeDefinitionRepository.findByConnectorUuidAndAttributeUuid(connectorAuthority.getUuid(), UUID.fromString(dataAttributeV3.getUuid())).orElseThrow();
        Assertions.assertEquals(dataAttributeV3.getContent().getFirst().getData(), ((List<AttributeContent>) attributeDefinition3.getDefinition().getContent()).getFirst().getData());
    }

    @Test
    void testGetCustomAttributesByResource() throws AttributeException {
        CustomAttributeProperties properties = expirationDateCustomAttribute.getProperties();
        properties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        attributeEngine.updateCustomAttributeDefinition(expirationDateCustomAttribute, List.of(Resource.CERTIFICATE));

        List<CustomAttribute> customAttributes = attributeEngine.getCustomAttributesByResource(Resource.CERTIFICATE, SecurityResourceFilter.create());
        Assertions.assertEquals(3, customAttributes.size());
        Assertions.assertTrue(customAttributes.stream().anyMatch(attr -> attr.getUuid().equals(departmentCustomAttribute.getUuid())));
        Assertions.assertTrue(customAttributes.stream().anyMatch(attr -> attr.getUuid().equals(orderNoCustomAttribute.getUuid())));
        Assertions.assertTrue(customAttributes.stream().anyMatch(attr -> attr.getUuid().equals(expirationDateCustomAttribute.getUuid())));

        AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByConnectorUuidAndAttributeUuid(null, UUID.fromString(expirationDateCustomAttribute.getUuid())).orElseThrow();
        Assertions.assertNull(((List<AttributeContent>) attributeDefinition.getDefinition().getContent()).getFirst().getData());
    }

    @Test
    void testGetResponseAttributesFromBaseAttributes() {
        DataAttributeV2 dataAttributeV2 = new DataAttributeV2();
        dataAttributeV2.setUuid(UUID.randomUUID().toString());
        dataAttributeV2.setName("name");
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("label");
        dataAttributeV2.setProperties(properties);
        dataAttributeV2.setContent(List.of(new StringAttributeContentV2("data")));
        dataAttributeV2.setContentType(AttributeContentType.STRING);
        List<ResponseAttribute> responseAttributes = AttributeEngine.getResponseAttributesFromBaseAttributes(List.of(departmentCustomAttribute, dataAttributeV2));
        Assertions.assertEquals(2, responseAttributes.size());
        Assertions.assertEquals(departmentCustomAttribute.getContent(), responseAttributes.getFirst().getContent());
        Assertions.assertEquals(dataAttributeV2.getContent(), responseAttributes.getLast().getContent());
        Assertions.assertEquals(dataAttributeV2.getProperties().getLabel(), responseAttributes.getLast().getLabel());
    }

    @Test
    void validateCodeBlockAttributeContent() throws AttributeException {
        DataAttributeV2 codeBlockData = new DataAttributeV2();
        codeBlockData.setContentType(AttributeContentType.CODEBLOCK);
        codeBlockData.setUuid(UUID.randomUUID().toString());
        codeBlockData.setName("testAttribute");
        codeBlockData.setType(AttributeType.DATA);

        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Test Label");
        props.setRequired(true);
        props.setReadOnly(false);
        props.setVisible(false);
        props.setList(false);
        codeBlockData.setProperties(props);
        UUID connectorUuid = connectorAuthority.getUuid();
        List<BaseAttribute> codeBlockDataList = List.of(codeBlockData);
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, codeBlockDataList);

        RequestAttributeV2 requestAttribute = new RequestAttributeV2();
        requestAttribute.setUuid(UUID.fromString(codeBlockData.getUuid()));
        requestAttribute.setName(codeBlockData.getName());
        requestAttribute.setContentType(codeBlockData.getContentType());
        requestAttribute.setContent(List.of(new StringAttributeContentV2("bad content")));

        List<RequestAttribute> requestAttributeList = List.of(requestAttribute);
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateUpdateDataAttributes(connectorUuid, null, codeBlockDataList, requestAttributeList));

        CodeBlockAttributeContentV2 attributeContent = new CodeBlockAttributeContentV2();
        attributeContent.setData(new CodeBlockAttributeContentData(null, ""));
        requestAttribute.setContent(List.of(attributeContent));
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateUpdateDataAttributes(connectorUuid, null, codeBlockDataList, requestAttributeList));

        attributeContent.setData(new CodeBlockAttributeContentData(ProgrammingLanguageEnum.PYTHON, "abc"));
        requestAttribute.setContent(List.of(attributeContent));
        Assertions.assertDoesNotThrow(() -> attributeEngine.validateUpdateDataAttributes(connectorUuid, null, codeBlockDataList, requestAttributeList));
    }

    @Test
    void testDeleteAllObjectAttributeContent() throws NotFoundException, CertificateException, IOException {
        attributeEngine.deleteObjectAttributeContent(Resource.CERTIFICATE, certificate.getUuid());
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));

        Assertions.assertTrue(certificateDetailDto.getMetadata().isEmpty());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());
    }

    @Test
    void testDeleteObjectCustomAttributesContent() throws NotFoundException, CertificateException, IOException, AttributeException {
        RequestAttributeV3 departmentAttributeDto = new RequestAttributeV3();
        departmentAttributeDto.setUuid(UUID.fromString(departmentCustomAttribute.getUuid()));
        departmentAttributeDto.setName(departmentCustomAttribute.getName());
        departmentAttributeDto.setContent(List.of(new StringAttributeContentV3("Sales")));

        RequestAttributeV3 orderNoAttributeDto = new RequestAttributeV3();
        orderNoAttributeDto.setUuid(UUID.fromString(orderNoCustomAttribute.getUuid()));
        orderNoAttributeDto.setName(orderNoCustomAttribute.getName());
        orderNoAttributeDto.setContent(List.of(new FloatAttributeContentV3(555f)));
        attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), List.of(departmentAttributeDto, orderNoAttributeDto));

        SecurityResourceFilter filter = new SecurityResourceFilter(List.of(departmentCustomAttribute.getUuid()), List.of(), true);
        attributeEngine.deleteObjectAllowedCustomAttributeContent(filter, Resource.CERTIFICATE, certificate.getUuid());
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));
        Assertions.assertEquals(1, certificateDetailDto.getCustomAttributes().size());
        Assertions.assertEquals(orderNoCustomAttribute.getUuid(), certificateDetailDto.getCustomAttributes().getFirst().getUuid().toString());

        filter = new SecurityResourceFilter(List.of(), List.of(expirationDateCustomAttribute.getUuid(), orderNoCustomAttribute.getUuid()), false);
        attributeEngine.deleteObjectAllowedCustomAttributeContent(filter, Resource.CERTIFICATE, certificate.getUuid());
        certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));
        Assertions.assertEquals(1, certificateDetailDto.getCustomAttributes().size());
        Assertions.assertEquals(orderNoCustomAttribute.getUuid(), certificateDetailDto.getCustomAttributes().getFirst().getUuid().toString());
    }

    @Test
    void testDeleteDefinitionAttributeContent() throws NotFoundException, CertificateException, IOException {
        attributeEngine.deleteAttributeDefinition(AttributeType.CUSTOM, UUID.fromString(departmentCustomAttribute.getUuid()));
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));

        Assertions.assertEquals(3, certificateDetailDto.getMetadata().size());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());

        attributeEngine.deleteAttributeDefinition(AttributeType.META, connectorDiscovery.getUuid(), UUID.fromString(networkDiscoveryMeta.getUuid()), networkDiscoveryMeta.getName());

        Assertions.assertFalse(certificateDetailDto.getMetadata().isEmpty());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());

        certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));
        Assertions.assertEquals(2, certificateDetailDto.getMetadata().size());
        Assertions.assertTrue(certificateDetailDto.getCustomAttributes().isEmpty());
    }

    private void loadCustomAttributesData() throws AttributeException, NotFoundException {
        departmentCustomAttribute = new CustomAttributeV3();
        departmentCustomAttribute.setUuid(UUID.randomUUID().toString());
        departmentCustomAttribute.setName("department");
        departmentCustomAttribute.setType(AttributeType.CUSTOM);
        departmentCustomAttribute.setContentType(AttributeContentType.STRING);

        CustomAttributeProperties customProps1 = new CustomAttributeProperties();
        customProps1.setLabel("Department");
        customProps1.setRequired(true);
        departmentCustomAttribute.setProperties(customProps1);

        orderNoCustomAttribute = new CustomAttributeV3();
        orderNoCustomAttribute.setUuid(UUID.randomUUID().toString());
        orderNoCustomAttribute.setName("order_no");
        orderNoCustomAttribute.setType(AttributeType.CUSTOM);
        orderNoCustomAttribute.setContentType(AttributeContentType.FLOAT);

        CustomAttributeProperties customProps2 = new CustomAttributeProperties();
        customProps2.setLabel("Order number");
        orderNoCustomAttribute.setProperties(customProps2);

        expirationDateCustomAttribute = new CustomAttributeV3();
        expirationDateCustomAttribute.setUuid(UUID.randomUUID().toString());
        expirationDateCustomAttribute.setName("expiration_date");
        expirationDateCustomAttribute.setType(AttributeType.CUSTOM);
        expirationDateCustomAttribute.setContentType(AttributeContentType.DATE);
        expirationDateCustomAttribute.setContent(List.of(new DateAttributeContentV3(LocalDate.EPOCH)));

        CustomAttributeProperties customProps3 = new CustomAttributeProperties();
        customProps3.setLabel("Expiration date");
        customProps3.setReadOnly(true);
        expirationDateCustomAttribute.setProperties(customProps3);

        attributeEngine.updateCustomAttributeDefinition(orderNoCustomAttribute, List.of(Resource.CERTIFICATE));
        attributeEngine.updateCustomAttributeDefinition(departmentCustomAttribute, List.of(Resource.CERTIFICATE, Resource.AUTHORITY));
        attributeEngine.updateCustomAttributeDefinition(expirationDateCustomAttribute, List.of(Resource.CERTIFICATE));

        RequestAttributeV3 departmentAttributeDto = new RequestAttributeV3();
        departmentAttributeDto.setUuid(UUID.fromString(departmentCustomAttribute.getUuid()));
        departmentAttributeDto.setName(departmentCustomAttribute.getName());
        departmentAttributeDto.setContent(List.of(new StringAttributeContentV3("Sales")));
        attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), List.of(departmentAttributeDto));
    }

    @Test
    void testDeleteConnectorAttributeDefinitionsContent() throws AttributeException, NotFoundException {
        // Create a DATA attribute definition for connectorDiscovery
        DataAttributeV3 dataAttribute = new DataAttributeV3();
        dataAttribute.setUuid(UUID.randomUUID().toString());
        dataAttribute.setName("data_attr");
        dataAttribute.setType(AttributeType.DATA);
        dataAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties dataProps = new DataAttributeProperties();
        dataProps.setLabel("Data Attr");
        dataAttribute.setProperties(dataProps);

        attributeEngine.updateDataAttributeDefinitions(connectorDiscovery.getUuid(), null, List.of(dataAttribute));

        // Create content for it
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(dataAttribute.getUuid()));
        requestAttribute.setName(dataAttribute.getName());
        requestAttribute.setContent(List.of(new StringAttributeContentV3("data_value")));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).build(), List.of(requestAttribute));

        // Verify it exists
        Assertions.assertFalse(attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.DATA, connectorDiscovery.getUuid(), UUID.fromString(dataAttribute.getUuid()), dataAttribute.getName()).isEmpty());
        Assertions.assertFalse(attributeContent2ObjectRepository.getObjectDataAttributesContentNoOperation(AttributeType.DATA, connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), null).isEmpty());

        // Delete connector attribute definitions content
        attributeEngine.deleteConnectorAttributeDefinitionsContent(connectorDiscovery.getUuid());

        // Verify it's gone
        Assertions.assertTrue(attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.DATA, connectorDiscovery.getUuid(), UUID.fromString(dataAttribute.getUuid()), dataAttribute.getName()).isEmpty());
        Assertions.assertTrue(attributeContent2ObjectRepository.getObjectDataAttributesContentNoOperation(AttributeType.DATA, connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), null).isEmpty());
    }

    @Test
    void testBulkDeleteObjectAttributeContent() throws AttributeException, NotFoundException {
        // Use existing certificate and create another one
        Certificate certificate2 = new Certificate();
        certificate2.setFingerprint("fingerprint2");
        certificate2.setSubjectDn("CN=test2");
        certificate2.setIssuerDn("CN=test2");
        certificate2.setSerialNumber("2");
        certificate2 = certificateRepository.save(certificate2);

        // Add some attributes to both
        RequestAttributeV3 departmentAttributeDto = new RequestAttributeV3();
        departmentAttributeDto.setUuid(UUID.fromString(departmentCustomAttribute.getUuid()));
        departmentAttributeDto.setName(departmentCustomAttribute.getName());
        departmentAttributeDto.setContent(List.of(new StringAttributeContentV3("Sales")));

        attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), List.of(departmentAttributeDto));
        attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate2.getUuid(), List.of(departmentAttributeDto));

        // Verify content exists
        Assertions.assertFalse(attributeContent2ObjectRepository.getObjectCustomAttributesContent(AttributeType.CUSTOM, Resource.CERTIFICATE, certificate.getUuid(), null, null).isEmpty());
        Assertions.assertFalse(attributeContent2ObjectRepository.getObjectCustomAttributesContent(AttributeType.CUSTOM, Resource.CERTIFICATE, certificate2.getUuid(), null, null).isEmpty());

        // Bulk delete
        attributeEngine.bulkDeleteObjectAttributeContent(Resource.CERTIFICATE, List.of(certificate.getUuid(), certificate2.getUuid()));

        // Verify content is gone
        Assertions.assertTrue(attributeContent2ObjectRepository.getObjectCustomAttributesContent(AttributeType.CUSTOM, Resource.CERTIFICATE, certificate.getUuid(), null, null).isEmpty());
        Assertions.assertTrue(attributeContent2ObjectRepository.getObjectCustomAttributesContent(AttributeType.CUSTOM, Resource.CERTIFICATE, certificate2.getUuid(), null, null).isEmpty());
    }

    @Test
    void testDeleteObjectAttributesContent() throws AttributeException, NotFoundException {
        // Create content for a data attribute
        DataAttributeV3 dataAttribute = new DataAttributeV3();
        dataAttribute.setUuid(UUID.randomUUID().toString());
        dataAttribute.setName("data_attr_del");
        dataAttribute.setType(AttributeType.DATA);
        dataAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties dataProps = new DataAttributeProperties();
        dataProps.setLabel("Data Attr Del");
        dataAttribute.setProperties(dataProps);

        attributeEngine.updateDataAttributeDefinitions(connectorDiscovery.getUuid(), null, List.of(dataAttribute));

        ObjectAttributeContentInfo contentInfo = ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).build();
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(dataAttribute.getUuid()));
        requestAttribute.setName(dataAttribute.getName());
        requestAttribute.setContent(List.of(new StringAttributeContentV3("data_value")));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).build(), List.of(requestAttribute));

        // Verify content exists
        Assertions.assertFalse(attributeContent2ObjectRepository.getObjectDataAttributesContentNoOperation(AttributeType.DATA, connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), null).isEmpty());

        // Delete object attributes content
        attributeEngine.deleteObjectAttributesContent(AttributeType.DATA, contentInfo);

        // Verify content is gone
        Assertions.assertTrue(attributeContent2ObjectRepository.getObjectDataAttributesContentNoOperation(AttributeType.DATA, connectorDiscovery.getUuid(), Resource.CERTIFICATE, certificate.getUuid(), null).isEmpty());
    }

    @Test
    void testDeleteOperationObjectAttributesContent() throws AttributeException, NotFoundException {
        // Create content for a data attribute with operation
        DataAttributeV3 dataAttribute = new DataAttributeV3();
        dataAttribute.setUuid(UUID.randomUUID().toString());
        dataAttribute.setName("data_attr_op_purp");
        dataAttribute.setType(AttributeType.DATA);
        dataAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties dataProps = new DataAttributeProperties();
        dataProps.setLabel("Data Attr Op Purp");
        dataAttribute.setProperties(dataProps);

        String operation = "testOperation";
        String purpose = "testPurpose";
        attributeEngine.updateDataAttributeDefinitions(connectorDiscovery.getUuid(), operation, List.of(dataAttribute));

        ObjectAttributeContentInfo contentInfo = ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).operation(operation).purpose(purpose).build();
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(dataAttribute.getUuid()));
        requestAttribute.setName(dataAttribute.getName());
        requestAttribute.setContent(List.of(new StringAttributeContentV3("op_purp_value")));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).operation(operation).purpose(purpose).build(), List.of(requestAttribute));

        // Verify content exists
        Assertions.assertFalse(attributeContent2ObjectRepository.getObjectDataAttributesContent(AttributeType.DATA, connectorDiscovery.getUuid(), operation, purpose, Resource.CERTIFICATE, certificate.getUuid(), null).isEmpty());

        // Delete operation object attributes content with purpose
        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, contentInfo);

        // Verify content is gone
        Assertions.assertTrue(attributeContent2ObjectRepository.getObjectDataAttributesContent(AttributeType.DATA, connectorDiscovery.getUuid(), operation, purpose, Resource.CERTIFICATE, certificate.getUuid(), null).isEmpty());
    }

    /**
     * Verifies that {@code getObjectCustomAttributesContent} correctly filters results when a non-null {@code allowedDefinitionUuids}
     * or {@code forbiddenDefinitionUuids} list is provided, and that passing {@code null} for both returns all attributes.
     */
    @Test
    void testGetObjectCustomAttributesContentFiltering() throws AttributeException, NotFoundException {
        // Assign content to both department and orderNo custom attributes on the certificate.
        // (expirationDateCustomAttribute is read-only and already has content from setup, but its
        //  content is assigned to Resource.CERTIFICATE via loadCustomAttributesData so all three
        //  definitions are linked. We assign runtime content only to the two non-read-only ones.)
        RequestAttributeV3 dept = new RequestAttributeV3();
        dept.setUuid(UUID.fromString(departmentCustomAttribute.getUuid()));
        dept.setName(departmentCustomAttribute.getName());
        dept.setContent(List.of(new StringAttributeContentV3("Engineering")));

        RequestAttributeV3 orderNo = new RequestAttributeV3();
        orderNo.setUuid(UUID.fromString(orderNoCustomAttribute.getUuid()));
        orderNo.setName(orderNoCustomAttribute.getName());
        orderNo.setContent(List.of(new FloatAttributeContentV3(42f)));

        attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), List.of(dept, orderNo));

        UUID deptUuid = UUID.fromString(departmentCustomAttribute.getUuid());
        UUID orderUuid = UUID.fromString(orderNoCustomAttribute.getUuid());

        // ── null / null → returns all stored attributes ──────────────────────
        var all = attributeContent2ObjectRepository.getObjectCustomAttributesContent(
                AttributeType.CUSTOM, Resource.CERTIFICATE, certificate.getUuid(), null, null);
        Assertions.assertTrue(all.size() >= 2, "null/null filter must return all attributes (got " + all.size() + ")");

        // ── allowedDefinitionUuids = [dept] → only dept is returned ──────────
        var allowed = attributeContent2ObjectRepository.getObjectCustomAttributesContent(
                AttributeType.CUSTOM, Resource.CERTIFICATE, certificate.getUuid(),
                List.of(deptUuid), null);
        Assertions.assertEquals(1, allowed.size(), "allow-list with only dept UUID must return exactly one attribute");
        Assertions.assertEquals(deptUuid, allowed.getFirst().uuid(),
                "the returned attribute must be the department one");

        // ── forbiddenDefinitionUuids = [dept] → dept is excluded ─────────────
        var forbidden = attributeContent2ObjectRepository.getObjectCustomAttributesContent(
                AttributeType.CUSTOM, Resource.CERTIFICATE, certificate.getUuid(),
                null, List.of(deptUuid));
        boolean containsDept = forbidden.stream().anyMatch(c -> deptUuid.equals(c.uuid()));
        Assertions.assertFalse(containsDept, "deny-list must not return the department attribute");
        boolean containsOrderNo = forbidden.stream().anyMatch(c -> orderUuid.equals(c.uuid()));
        Assertions.assertTrue(containsOrderNo, "deny-list must still return the orderNo attribute");
    }

    @Test
    void testGetResponseAttributesFromRequestAttributes() {
        RequestAttributeV2 requestAttributeV2 = new RequestAttributeV2();
        requestAttributeV2.setContent(List.of(new DateAttributeContentV2(LocalDate.now())));
        RequestAttributeV3 requestAttributeV3 = new RequestAttributeV3();
        requestAttributeV3.setContent(List.of(new StringAttributeContentV3("STR")));
        List<ResponseAttribute> responseAttributes = AttributeEngine.getResponseAttributesFromRequestAttributes(List.of(requestAttributeV2, requestAttributeV3));
        Assertions.assertEquals(2, responseAttributes.size());
        Assertions.assertNotNull(responseAttributes.getFirst().getContent());
        Assertions.assertNotNull(responseAttributes.getLast().getContent());

    }

    @Test
    void testNotUpdatingAttributeDefinitionWhenLoading() {
        AttributeDefinition attributeDefinition = getAttributeDefinition("name", "label", AttributeType.CUSTOM, departmentCustomAttribute);
        LocalDateTime updatedAt = attributeDefinition.getUpdatedAt();

        AttributeRelation attributeRelation = new AttributeRelation();
        attributeRelation.setAttributeDefinition(attributeDefinition);
        attributeRelation.setResource(Resource.ACME_ACCOUNT);
        attributeRelationRepository.save(attributeRelation);

        attributeEngine.getCustomAttributesByResource(attributeRelation.getResource(), SecurityResourceFilter.create());
        attributeDefinition = attributeDefinitionRepository.findByAttributeUuid(attributeDefinition.getAttributeUuid()).get();
        Assertions.assertEquals(updatedAt.truncatedTo(ChronoUnit.MILLIS), attributeDefinition.getUpdatedAt().truncatedTo(ChronoUnit.MILLIS));

        DataAttributeV2 dataAttribute = new DataAttributeV2();
        dataAttribute.setContentType(AttributeContentType.STRING);
        dataAttribute.setContent(List.of(new BaseAttributeContentV2<>("ref", "data")));
        AttributeDefinition attributeDataDefinition = getAttributeDefinition("nameData", "labelData", AttributeType.DATA, dataAttribute);
        LocalDateTime updatedAtData = attributeDataDefinition.getUpdatedAt();

        attributeEngine.getDataAttributeDefinition(null, attributeDataDefinition.getName());
        attributeDataDefinition = attributeDefinitionRepository.findByAttributeUuid(attributeDataDefinition.getAttributeUuid()).get();
        Assertions.assertEquals(updatedAtData.truncatedTo(ChronoUnit.MILLIS), attributeDataDefinition.getUpdatedAt().truncatedTo(ChronoUnit.MILLIS));
    }

    @NotNull
    private AttributeDefinition getAttributeDefinition(String name, String label, AttributeType attributeType, BaseAttribute definition) {
        AttributeDefinition attributeDefinition = new AttributeDefinition();
        attributeDefinition.setName(name);
        attributeDefinition.setAttributeUuid(UUID.randomUUID());
        attributeDefinition.setLabel(label);
        attributeDefinition.setType(attributeType);
        attributeDefinition.setContentType(AttributeContentType.STRING);
        attributeDefinition.setDefinition(definition);
        attributeDefinitionRepository.save(attributeDefinition);
        return attributeDefinition;
    }

    private void loadMetadata() throws AttributeException {
        networkDiscoveryMeta = new MetadataAttributeV3();
        networkDiscoveryMeta.setName("discoverySource");
        networkDiscoveryMeta.setUuid("000043aa-6022-11ed-9b6a-0242ac120002");
        networkDiscoveryMeta.setContentType(AttributeContentType.STRING);
        networkDiscoveryMeta.setType(AttributeType.META);
        networkDiscoveryMeta.setDescription("Source from where the certificate is discovered");
        MetadataAttributeProperties metaProps1 = new MetadataAttributeProperties();
        metaProps1.setLabel("Discovery Source");
        metaProps1.setVisible(true);
        metaProps1.setGlobal(true);
        networkDiscoveryMeta.setProperties(metaProps1);
        networkDiscoveryMeta.setContent(List.of(new StringAttributeContentV3("localhost:0443")));
        attributeEngine.updateMetadataAttribute(networkDiscoveryMeta, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorDiscovery.getUuid()).source(Resource.DISCOVERY, networkDiscoveryUuid).build());

        MetadataAttributeV2 authorityDiscoveryMeta = new MetadataAttributeV2();
        authorityDiscoveryMeta.setName("username");
        authorityDiscoveryMeta.setUuid("df2fbaa2-60fd-11ed-9b6a-0242ac120002");
        authorityDiscoveryMeta.setContentType(AttributeContentType.STRING);
        authorityDiscoveryMeta.setType(AttributeType.META);
        authorityDiscoveryMeta.setDescription("Username of certificate");
        MetadataAttributeProperties metaProps2 = new MetadataAttributeProperties();
        metaProps2.setLabel("Username");
        metaProps2.setVisible(true);
        authorityDiscoveryMeta.setProperties(metaProps2);
        authorityDiscoveryMeta.setContent(List.of(new StringAttributeContentV2("tst-username")));
        attributeEngine.updateMetadataAttribute(authorityDiscoveryMeta, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorAuthority.getUuid()).source(Resource.DISCOVERY, authorityDiscoveryUuid).build());

        MetadataAttributeV2 authorityIssueMeta = new MetadataAttributeV2();
        authorityIssueMeta.setUuid("b42ab690-60fd-11ed-9b6a-0242ac120002");
        authorityIssueMeta.setName("ejbcaUsername");
        authorityIssueMeta.setDescription("EJBCA Username");
        authorityIssueMeta.setType(AttributeType.META);
        authorityIssueMeta.setContentType(AttributeContentType.STRING);
        authorityIssueMeta.setContent(List.of(new StringAttributeContentV2("tst-ejbcaUsername==")));
        MetadataAttributeProperties metaProps3 = new MetadataAttributeProperties();
        metaProps3.setVisible(true);
        metaProps3.setLabel("EJBCA Username");
        authorityIssueMeta.setProperties(metaProps3);
        attributeEngine.updateMetadataAttribute(authorityIssueMeta, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorAuthority.getUuid()).build());
    }

    @Test
    void getRequestDataAttributesContentReturnsCorrectResponse() throws AttributeException {
        // Arrange
        DataAttributeV2 dataAttribute = new DataAttributeV2();
        dataAttribute.setUuid(UUID.randomUUID().toString());
        dataAttribute.setName("testAttribute");
        dataAttribute.setType(AttributeType.DATA);
        dataAttribute.setContentType(AttributeContentType.STRING);

        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Test Label");
        props.setRequired(true);
        props.setReadOnly(false);
        props.setVisible(false);
        props.setList(false);
        dataAttribute.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(dataAttribute));

        RequestAttributeV2 requestAttribute = new RequestAttributeV2();
        requestAttribute.setUuid(UUID.fromString(dataAttribute.getUuid()));
        requestAttribute.setName(dataAttribute.getName());
        requestAttribute.setContentType(dataAttribute.getContentType());
        requestAttribute.setContent(List.of(new StringAttributeContentV2("testValue")));

        // Act
        List<ResponseAttribute> responseAttributes = attributeEngine.getRequestDataAttributesContent(List.of(dataAttribute), List.of(requestAttribute));

        // Assert
        Assertions.assertEquals(1, responseAttributes.size());
        Assertions.assertEquals(dataAttribute.getUuid(), responseAttributes.getFirst().getUuid().toString());
        Assertions.assertEquals(dataAttribute.getName(), responseAttributes.getFirst().getName());
        Assertions.assertEquals(dataAttribute.getProperties().getLabel(), responseAttributes.getFirst().getLabel());
        Assertions.assertEquals(requestAttribute.getContent(), responseAttributes.getFirst().getContent());
    }

    @Test
    void testAttributeEncryption() throws AttributeException, NotFoundException {
        testAttributeEncryption(AttributeContentType.STRING, new StringAttributeContentV3("sensitiveData"), "sensitiveData");
        testAttributeEncryption(AttributeContentType.INTEGER, new IntegerAttributeContentV3(1), 1);
        testAttributeEncryption(AttributeContentType.TEXT, new TextAttributeContentV3("text"), "text");
        testAttributeEncryption(AttributeContentType.DATE, new DateAttributeContentV3(LocalDate.of(2024, 1, 1)), LocalDate.of(2024, 1, 1));
        testAttributeEncryption(AttributeContentType.TIME, new TimeAttributeContentV3(LocalTime.of(12, 0)), LocalTime.of(12, 0));
        testAttributeEncryption(AttributeContentType.DATETIME, new DateTimeAttributeContentV3(ZonedDateTime.parse("2024-01-01T12:00:00+00:00")), ZonedDateTime.parse("2024-01-01T12:00:00+00:00"));
        FileAttributeContentData fileAttributeContentData = new FileAttributeContentData();
        fileAttributeContentData.setContent("test");
        fileAttributeContentData.setFileName("filename.txt");
        fileAttributeContentData.setMimeType("text/plain");
        testAttributeEncryption(AttributeContentType.FILE, new FileAttributeContentV3("filename.txt", fileAttributeContentData), fileAttributeContentData);
        testAttributeEncryption(AttributeContentType.FLOAT, new FloatAttributeContentV3(1.5f), 1.5f);
        testAttributeEncryption(AttributeContentType.OBJECT, new ObjectAttributeContentV3("{\"key\":\"value\"}"), "{\"key\":\"value\"}");
        CodeBlockAttributeContentData codeBlockAttributeContentData = new CodeBlockAttributeContentData(ProgrammingLanguageEnum.PYTHON, "print('Hello, World!')");
        testAttributeEncryption(AttributeContentType.CODEBLOCK, new CodeBlockAttributeContentV3("ref", codeBlockAttributeContentData), codeBlockAttributeContentData);
        testAttributeEncryption(AttributeContentType.BOOLEAN, new BooleanAttributeContentV3(true), true);
        ResourceSimpleContentData resourceObjectContentData = new ResourceSimpleContentData(AttributeResource.AUTHORITY);
        resourceObjectContentData.setAttributes(List.of(new ResponseAttributeV3()));
        resourceObjectContentData.setUuid(UUID.randomUUID().toString());
        resourceObjectContentData.setName("name");
        testAttributeEncryption(AttributeContentType.RESOURCE, new ResourceObjectContent("ref", resourceObjectContentData), resourceObjectContentData);
    }


    private void testAttributeEncryption(AttributeContentType contentType, BaseAttributeContentV3<?> contentV3, Object data) throws AttributeException, NotFoundException {
        DataAttributeV3 secretAttribute = new DataAttributeV3();
        secretAttribute.setUuid(UUID.randomUUID().toString());
        secretAttribute.setName("secretAttribute");
        secretAttribute.setType(AttributeType.DATA);
        secretAttribute.setContentType(contentType);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        properties.setLabel("Secret Attribute");
        properties.setResource(AttributeResource.AUTHORITY);
        secretAttribute.setProperties(properties);
        secretAttribute.setAttributeCallback(new AttributeCallback());
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(secretAttribute));
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(secretAttribute.getUuid()));
        requestAttribute.setName(secretAttribute.getName());
        requestAttribute.setContentType(secretAttribute.getContentType());
        requestAttribute.setContent(List.of(contentV3));
        List<ResponseAttribute> responseAttributes = attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorAuthority.getUuid()).build(),
                List.of(requestAttribute)
        );
        Assertions.assertEquals(1, responseAttributes.size());
        ResponseAttributeV3 responseAttribute = (ResponseAttributeV3) responseAttributes.getFirst();
        Assertions.assertNotNull(responseAttribute.getContent().getFirst().getData());
        UUID definitionUuid = attributeDefinitionRepository.findByAttributeUuid(UUID.fromString(secretAttribute.getUuid())).orElseThrow().getUuid();
        AttributeContentItem attributeContentItem = attributeContentItemRepository.findByAttributeDefinitionUuid(definitionUuid).getFirst();
        Assertions.assertNotEquals(contentV3, attributeContentItem.getJson());
        Assertions.assertNotNull(attributeContentItem.getEncryptedData());

        // Decrypt check
        List<RequestAttribute> decryptedAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorAuthority.getUuid()).build());
        List<BaseAttributeContentV3<?>> content1 = decryptedAttributes.getFirst().getContent();
        Assertions.assertEquals(data, content1.getFirst().getData());
    }


    @Test
    void validateRequestDataAttributesThrowsValidationExceptionForMissingRequiredAttributes() throws AttributeException {
        // Arrange
        DataAttributeV2 requiredAttribute = new DataAttributeV2();
        requiredAttribute.setUuid(UUID.randomUUID().toString());
        requiredAttribute.setName("requiredAttribute");
        requiredAttribute.setType(AttributeType.DATA);
        requiredAttribute.setContentType(AttributeContentType.STRING);
        RegexpAttributeConstraint constraint = new RegexpAttributeConstraint();
        constraint.setData("^[a-zA-Z]+$");
        requiredAttribute.setConstraints(List.of(constraint));

        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Required Label");
        props.setRequired(true);
        props.setReadOnly(false);
        props.setVisible(false);
        props.setList(false);
        requiredAttribute.setProperties(props);
        UUID connectorUuid = connectorAuthority.getUuid();
        List<BaseAttribute> requiredAttributeList = List.of(requiredAttribute);
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, requiredAttributeList);

        RequestAttributeV2 requestAttribute = new RequestAttributeV2();
        requestAttribute.setUuid(UUID.randomUUID());
        requestAttribute.setName("unrelatedAttribute");
        requestAttribute.setContentType(AttributeContentType.STRING);
        requestAttribute.setContent(List.of(new StringAttributeContentV2("value")));

        // Act
        List<RequestAttribute> requestAttributeList = List.of(requestAttribute);
        Executable executable = () -> AttributeEngine.validateRequestDataAttributes(requiredAttributeList, requestAttributeList, true);

        // Assert
        Assertions.assertThrows(ValidationException.class, executable);

        // Test constraints

        requestAttribute.setUuid(UUID.fromString(requiredAttribute.getUuid()));
        requestAttribute.setName(requiredAttribute.getName());
        Assertions.assertDoesNotThrow(() -> attributeEngine.validateUpdateDataAttributes(connectorUuid, null, requiredAttributeList, requestAttributeList));

        requestAttribute.setContent(List.of(new StringAttributeContentV2("value123")));
        Assertions.assertThrows(ValidationException.class, () -> attributeEngine.validateUpdateDataAttributes(connectorUuid, null, requiredAttributeList, requestAttributeList));

    }

    @Test
    void testUpdateAttributeDefinition() throws AttributeException {
        DataAttributeV3 validAttribute = new DataAttributeV3();
        validAttribute.setUuid(UUID.randomUUID().toString());
        validAttribute.setName("validAttribute");
        validAttribute.setType(AttributeType.DATA);
        validAttribute.setContentType(AttributeContentType.STRING);

        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Valid Label");
        props.setRequired(true);
        props.setReadOnly(false);
        props.setVisible(false);
        props.setList(false);
        validAttribute.setProperties(props);

        List<BaseAttributeConstraint<?>> constraints = new ArrayList<>();
        RegexpAttributeConstraint constraint = new RegexpAttributeConstraint("", "", ".");
        constraints.add(constraint);
        validAttribute.setConstraints(constraints);

        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(validAttribute));

        validAttribute.setConstraints(null);
        validAttribute.setAttributeCallback(new AttributeCallback());
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(validAttribute));

        DataAttribute dataAttribute = attributeEngine.getDataAttributeDefinition(connectorAuthority.getUuid(), validAttribute.getName());
        Assertions.assertNotNull(dataAttribute.getAttributeCallback());
        Assertions.assertNull(dataAttribute.getConstraints());
    }

    @Test
    void validateRequestDataAttributesPassesForValidAttributes() throws AttributeException {
        // Arrange
        DataAttributeV2 validAttribute = new DataAttributeV2();
        validAttribute.setUuid(UUID.randomUUID().toString());
        validAttribute.setName("validAttribute");
        validAttribute.setType(AttributeType.DATA);
        validAttribute.setContentType(AttributeContentType.STRING);

        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Valid Label");
        props.setRequired(true);
        props.setReadOnly(false);
        props.setVisible(false);
        props.setList(false);
        validAttribute.setProperties(props);

        List<DataAttributeV2> validAttributeList = List.of(validAttribute);
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, validAttributeList);

        RequestAttributeV2 requestAttribute = new RequestAttributeV2();
        requestAttribute.setUuid(UUID.fromString(validAttribute.getUuid()));
        requestAttribute.setName(validAttribute.getName());
        requestAttribute.setContentType(validAttribute.getContentType());
        requestAttribute.setContent(List.of(new StringAttributeContentV2("validValue")));

        // Act & Assert
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestDataAttributes(validAttributeList, List.of(requestAttribute), true));
    }

    @Test
    void testGetResourceSearchableFields() throws AttributeException {
        // Arrange
        DataAttributeV3 dataAttribute = new DataAttributeV3();
        dataAttribute.setUuid(UUID.randomUUID().toString());
        dataAttribute.setName("dataAttribute");
        dataAttribute.setType(AttributeType.DATA);
        dataAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties dataProps = new DataAttributeProperties();
        dataProps.setLabel("Data Label");
        dataAttribute.setProperties(dataProps);
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(dataAttribute));

        // Create relation for DATA attribute so it's found by the query
        AttributeDefinition dataAttrDef = attributeDefinitionRepository.findByTypeAndConnectorUuidAndName(AttributeType.DATA, connectorAuthority.getUuid(), dataAttribute.getName()).orElseThrow();
        AttributeRelation dataRelation = new AttributeRelation();
        dataRelation.setAttributeDefinition(dataAttrDef);
        dataRelation.setResource(Resource.CERTIFICATE);
        attributeRelationRepository.save(dataRelation);

        // Metadata already loaded in setUp via loadMetadata()

        // Act
        List<SearchFieldDataByGroupDto> searchableFields = attributeEngine.getResourceSearchableFields(Resource.CERTIFICATE, false);

        // Assert
        Assertions.assertNotNull(searchableFields);
        Assertions.assertFalse(searchableFields.isEmpty());

        var customFields = searchableFields.stream().filter(f -> f.getFilterFieldSource() == FilterFieldSource.CUSTOM).toList();
        var dataFields = searchableFields.stream().filter(f -> f.getFilterFieldSource() == FilterFieldSource.DATA).toList();
        var metaFields = searchableFields.stream().filter(f -> f.getFilterFieldSource() == FilterFieldSource.META).toList();

        Assertions.assertFalse(customFields.isEmpty());
        Assertions.assertEquals(1, customFields.size());
        Assertions.assertFalse(dataFields.isEmpty());
        Assertions.assertEquals(1, dataFields.size());
        Assertions.assertFalse(metaFields.isEmpty());
        Assertions.assertEquals(1, metaFields.size());
    }

    @Test
    void testGetResourceSettableFields() throws AttributeException {
        // Arrange
        DataAttributeV3 dataAttribute = new DataAttributeV3();
        dataAttribute.setUuid(UUID.randomUUID().toString());
        dataAttribute.setName("dataAttribute");
        dataAttribute.setType(AttributeType.DATA);
        dataAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties dataProps = new DataAttributeProperties();
        dataProps.setLabel("Data Label");
        dataAttribute.setProperties(dataProps);
        attributeEngine.updateDataAttributeDefinitions(connectorAuthority.getUuid(), null, List.of(dataAttribute));

        // Create relation for DATA attribute so it's found by the query
        AttributeDefinition dataAttrDef = attributeDefinitionRepository.findByTypeAndConnectorUuidAndName(AttributeType.DATA, connectorAuthority.getUuid(), dataAttribute.getName()).orElseThrow();
        AttributeRelation dataRelation = new AttributeRelation();
        dataRelation.setAttributeDefinition(dataAttrDef);
        dataRelation.setResource(Resource.CERTIFICATE);
        attributeRelationRepository.save(dataRelation);

        // Act
        List<SearchFieldDataByGroupDto> settableFields = attributeEngine.getResourceSearchableFields(Resource.CERTIFICATE, true);

        // Assert
        Assertions.assertNotNull(settableFields);

        var customFields = settableFields.stream().filter(f -> f.getFilterFieldSource() == FilterFieldSource.CUSTOM).toList();
        var dataFields = settableFields.stream().filter(f -> f.getFilterFieldSource() == FilterFieldSource.DATA).toList();
        var metaFields = settableFields.stream().filter(f -> f.getFilterFieldSource() == FilterFieldSource.META).toList();

        Assertions.assertFalse(customFields.isEmpty());
        Assertions.assertEquals(1, customFields.size());
        Assertions.assertTrue(dataFields.isEmpty());
        Assertions.assertTrue(metaFields.isEmpty());
    }
}
