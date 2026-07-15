package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.*;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.common.attribute.common.*;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.v2.*;
import com.otilm.api.model.common.attribute.v2.content.*;
import com.otilm.api.model.common.attribute.common.content.data.CodeBlockAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProgrammingLanguageEnum;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.GroupAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.*;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.common.attribute.v3.mapping.*;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.*;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceContext;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Month;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

class AttributeEngineITest extends BaseSpringBootTest {

    private static final String REGISTERED_EXTENSION_OID = "9.9.9.1";

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateExternalService certificateService;
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
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @PersistenceContext
    private EntityManager entityManager;

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

    private static void ensureOidCached(OidCategory category, String oid, OidRecord oidRecord) {
        Map<String, OidRecord> cache = OidHandler.getOidCache(category);
        if (cache == null) {
            OidHandler.cacheOidCategory(category, new HashMap<>());
            cache = OidHandler.getOidCache(category);
        }
        cache.put(oid, oidRecord);
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
    void updateDataAttributeDefinitionsKeepsExtensibleListOptionsOnResponseButNotInStorage() throws AttributeException {
        // The connector-provided options must survive on the returned attribute (a listing endpoint
        // returns that same object and the UI needs them as suggestions), while the persisted
        // definition is stored without them. Covers both copyWithoutContent branches (v3 and v2).
        DataAttributeV3 v3 = new DataAttributeV3();
        v3.setUuid(UUID.randomUUID().toString());
        v3.setName("extensibleListV3");
        v3.setContentType(AttributeContentType.STRING);
        v3.setContent(List.of(new StringAttributeContentV3("team-a")));
        DataAttributeProperties p3 = new DataAttributeProperties();
        p3.setLabel("Extensible list v3");
        p3.setList(true);
        p3.setExtensibleList(true);
        p3.setReadOnly(false);
        v3.setProperties(p3);

        attributeEngine.updateDataAttributeDefinitions(null, null, List.of(v3));

        Assertions.assertNotNull(v3.getContent(), "v3 options must survive for the response");
        Assertions.assertEquals("team-a", ((StringAttributeContentV3) v3.getContent().get(0)).getData());
        AttributeDefinition def3 = attributeDefinitionRepository.findByConnectorUuidAndAttributeUuid(null, UUID.fromString(v3.getUuid())).orElseThrow();
        Assertions.assertNull(def3.getDefinition().getContent(), "v3 definition must be stored without options");

        DataAttributeV2 v2 = new DataAttributeV2();
        v2.setUuid(UUID.randomUUID().toString());
        v2.setName("extensibleListV2");
        v2.setContentType(AttributeContentType.STRING);
        v2.setContent(List.of(new StringAttributeContentV2("team-b")));
        DataAttributeProperties p2 = new DataAttributeProperties();
        p2.setLabel("Extensible list v2");
        p2.setList(true);
        p2.setExtensibleList(true);
        p2.setReadOnly(false);
        v2.setProperties(p2);

        attributeEngine.updateDataAttributeDefinitions(null, null, List.of(v2));

        Assertions.assertNotNull(v2.getContent(), "v2 options must survive for the response");
        Assertions.assertEquals("team-b", ((StringAttributeContentV2) v2.getContent().get(0)).getData());
        AttributeDefinition def2 = attributeDefinitionRepository.findByConnectorUuidAndAttributeUuid(null, UUID.fromString(v2.getUuid())).orElseThrow();
        Assertions.assertNull(def2.getDefinition().getContent(), "v2 definition must be stored without options");
    }

    @Test
    void updateDataAttributeDefinitionsFailsLoudOnUnsupportedVersionExtensibleList() {
        // Guard: an extensible-list attribute whose version has no copy support must fail loudly
        // rather than silently mutating the caller's attribute in place.
        DataAttributeV2 unsupported = new DataAttributeV2();
        unsupported.setUuid(UUID.randomUUID().toString());
        unsupported.setName("unsupportedVersionExtensible");
        unsupported.setContentType(AttributeContentType.STRING);
        unsupported.setContent(List.of(new StringAttributeContentV2("x")));
        unsupported.setVersion(99);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Unsupported version");
        props.setList(true);
        props.setExtensibleList(true);
        props.setReadOnly(false);
        unsupported.setProperties(props);

        Assertions.assertThrows(IllegalStateException.class,
                () -> attributeEngine.updateDataAttributeDefinitions(null, null, List.of(unsupported)));
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
    void testDeleteConnectorAttributeDefinitionsContent_removesGroupDefinitions() throws AttributeException {
        GroupAttributeV3 groupAttribute = new GroupAttributeV3();
        groupAttribute.setUuid(UUID.randomUUID().toString());
        groupAttribute.setName("group_attr");
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/callback");
        callback.setCallbackMethod("GET");
        groupAttribute.setAttributeCallback(callback);

        attributeEngine.updateDataAttributeDefinitions(connectorDiscovery.getUuid(), null, List.of(groupAttribute));

        Assertions.assertTrue(attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.GROUP, connectorDiscovery.getUuid(), UUID.fromString(groupAttribute.getUuid()), groupAttribute.getName()).isPresent());

        attributeEngine.deleteConnectorAttributeDefinitionsContent(connectorDiscovery.getUuid());

        Assertions.assertTrue(attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.GROUP, connectorDiscovery.getUuid(), UUID.fromString(groupAttribute.getUuid()), groupAttribute.getName()).isEmpty(),
                "GROUP attribute definitions must be removed with the connector, otherwise deleting the connector violates fk_attribute_definition_connector");
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
    void updateMetadataAttributeDefinition_doesNotMutateCallerContent() throws AttributeException {
        // Arrange
        MetadataAttributeV3 metadataAttribute = new MetadataAttributeV3();
        metadataAttribute.setUuid(UUID.randomUUID().toString());
        metadataAttribute.setName("copyFixMeta");
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties props = new MetadataAttributeProperties();
        props.setLabel("Copy Fix Meta");
        props.setVisible(true);
        metadataAttribute.setProperties(props);
        metadataAttribute.setContent(List.of(new StringAttributeContentV3("replay-value")));

        // Act
        AttributeDefinition attributeDefinition = attributeEngine.updateMetadataAttributeDefinition(metadataAttribute, connectorAuthority.getUuid());

        // Assert: the caller's object must keep its content for later use (e.g. register->issue replay)
        Assertions.assertEquals(1, metadataAttribute.getContent().size());
        Assertions.assertEquals("replay-value", ((StringAttributeContentV3) metadataAttribute.getContent().getFirst()).getData());

        // Assert: the persisted definition must not carry content
        MetadataAttributeV3 storedDefinition = (MetadataAttributeV3) attributeDefinition.getDefinition();
        Assertions.assertTrue(storedDefinition.getContent().isEmpty());

        // Assert: reloading from the DB confirms the stripped copy (not the mutated caller object) was actually flushed
        AttributeDefinition reloaded = attributeDefinitionRepository.findByAttributeUuid(attributeDefinition.getAttributeUuid()).orElseThrow();
        MetadataAttributeV3 reloadedDefinition = (MetadataAttributeV3) reloaded.getDefinition();
        Assertions.assertTrue(reloadedDefinition.getContent().isEmpty());
    }

    @Test
    void updateMetadataAttributeDefinition_skipsUpdateWhenUnchangedButPersistsOnChange() {
        // given: a metadata definition already registered in its own committed transaction
        UUID attributeUuid = UUID.randomUUID();
        inNewTransaction(() -> updateMetadata(attributeUuid, "Skip Fix Meta"));

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        boolean statisticsWereEnabled = statistics.isStatisticsEnabled();
        statistics.setStatisticsEnabled(true);
        try {
            // when: the identical definition is resubmitted in a fresh transaction that forces a flush
            statistics.clear();
            inNewTransaction(() -> {
                updateMetadata(attributeUuid, "Skip Fix Meta");
                entityManager.flush(); // a still-dirty definition would emit its UPDATE here
            });

            // then: no UPDATE is issued for the unchanged definition row
            assertThat(attributeDefinitionUpdateCount(statistics))
                    .as("resubmitting an identical metadata definition must not issue a redundant UPDATE (issue #1819)")
                    .isZero();

            // when: the label changes and the definition is resubmitted
            statistics.clear();
            inNewTransaction(() -> {
                updateMetadata(attributeUuid, "Skip Fix Meta (changed)");
                entityManager.flush();
            });

            // then: exactly one UPDATE hits the definition row and the change is really in the database,
            // proving the skip is not swallowing genuine updates
            assertThat(attributeDefinitionUpdateCount(statistics))
                    .as("changing the label must persist an UPDATE on the definition row")
                    .isEqualTo(1);
            AttributeDefinition reloaded = attributeDefinitionRepository.findByAttributeUuid(attributeUuid).orElseThrow();
            assertThat(reloaded.getLabel()).isEqualTo("Skip Fix Meta (changed)");
        } finally {
            statistics.setStatisticsEnabled(statisticsWereEnabled);
        }
    }

    @Test
    void updateMetadataAttributeDefinition_persistsChangeAfterUnchangedResubmitInSameTransaction() {
        // given: a metadata definition already registered in its own committed transaction
        UUID attributeUuid = UUID.randomUUID();
        inNewTransaction(() -> updateMetadata(attributeUuid, "Same Tx Meta"));

        // when: a single transaction (single persistence context) resubmits the definition unchanged
        // and then submits a genuine change to the same managed entity
        inNewTransaction(() -> {
            updateMetadata(attributeUuid, "Same Tx Meta");
            updateMetadata(attributeUuid, "Same Tx Meta (changed)");
        });

        // then: the later change survives the earlier unchanged-skip within the same persistence context
        AttributeDefinition reloaded = inNewTransaction(
                () -> attributeDefinitionRepository.findByAttributeUuid(attributeUuid).orElseThrow());
        assertThat(reloaded.getLabel())
                .as("a change following an unchanged resubmit in the same transaction must not be dropped at flush")
                .isEqualTo("Same Tx Meta (changed)");
    }

    private static long attributeDefinitionUpdateCount(Statistics statistics) {
        return statistics.getEntityStatistics(AttributeDefinition.class.getName()).getUpdateCount();
    }

    private void updateMetadata(UUID attributeUuid, String label) {
        MetadataAttributeV3 metadataAttribute = new MetadataAttributeV3();
        metadataAttribute.setUuid(attributeUuid.toString());
        metadataAttribute.setName("skipFixMeta");
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties props = new MetadataAttributeProperties();
        props.setLabel(label);
        props.setVisible(true);
        metadataAttribute.setProperties(props);
        metadataAttribute.setContent(List.of(new StringAttributeContentV3("skip-value")));
        try {
            attributeEngine.updateMetadataAttributeDefinition(metadataAttribute, connectorAuthority.getUuid());
        } catch (AttributeException e) {
            throw new IllegalStateException(e);
        }
    }

    private void inNewTransaction(Runnable work) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template.executeWithoutResult(status -> work.run());
    }

    private <T> T inNewTransaction(Supplier<T> work) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template.execute(status -> work.get());
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
        testAttributeEncryption(AttributeContentType.DATE, new DateAttributeContentV3(LocalDate.of(2024, Month.JANUARY, 1)), LocalDate.of(2024, Month.JANUARY, 1));
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

    @Nested
    class ValidateMappedField {

        // Snapshot of the process-wide OidHandler cache taken before this class mutates it.
        private static final Map<OidCategory, Map<String, OidRecord>> savedOidCache = new EnumMap<>(OidCategory.class);

        @BeforeAll
        static void initOidCache() {
            for (OidCategory category : OidCategory.values()) {
                Map<String, OidRecord> existing = OidHandler.getOidCache(category);
                savedOidCache.put(category, existing == null ? null : new HashMap<>(existing));
                if (existing == null) {
                    OidHandler.cacheOidCategory(category, new HashMap<>());
                }
            }
        }

        @AfterAll
        static void restoreOidCache() {
            for (OidCategory category : OidCategory.values()) {
                Map<String, OidRecord> saved = savedOidCache.get(category);
                if (saved != null) {
                    OidHandler.cacheOidCategory(category, saved);
                }
            }
        }

        @BeforeEach
        void setUp() {
            // Re-seed OID entries that field-mapping tests depend on. The OID cache is loaded from DB
            // on Spring context startup; entries added here are not in the DB, so they must be
            // explicitly placed in the cache each time setUp() runs (before each test).
            ensureOidCached(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3", OidRecord.builder().displayName("Common Name").code("CN").altCodes(List.of()).build());
            ensureOidCached(OidCategory.CERTIFICATE_EXTENSION, REGISTERED_EXTENSION_OID, OidRecord.builder().displayName("Test Extension").build());
        }


        // ── validateFieldMapping / validateMappedField ────────────────────────────

        @Test
        void testFieldMapping_missingObjectType_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_no_obj_type");
            FieldMapping fm = new FieldMapping();
            fm.setObjectType(null);
            fm.setFields(List.of(rdnField("CN")));
            attr.setFieldMapping(fm);

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping.objectType is required"), ex::getMessage);
        }

        @Test
        void testFieldMapping_emptyFields_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_empty_fields");
            FieldMapping fm = new FieldMapping();
            fm.setObjectType(ObjectType.X509_CERTIFICATE);
            fm.setFields(List.of());
            attr.setFieldMapping(fm);

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping.fields must not be empty"), ex::getMessage);
        }

        @Test
        void testFieldMapping_rdnField_missingRdn_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_rdn_no_rdn");
            attr.setFieldMapping(fieldMappingWith(rdnField(null)));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping RDN field is missing rdn"), ex::getMessage);
        }

        @Test
        void testFieldMapping_rdnField_unknownCode_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_rdn_bad_code");
            attr.setFieldMapping(fieldMappingWith(rdnField("UNKNOWNCODE")));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("is not a known RDN code"), ex::getMessage);
        }

        @Test
        void testFieldMapping_rdnField_validCode_ok() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_rdn_valid_code");
            attr.setFieldMapping(fieldMappingWith(rdnField("CN")));

            UUID connectorUuid = connectorAuthority.getUuid();
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
        }

        @Test
        void testFieldMapping_rdnField_dottedOid_ok() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_rdn_dotted_oid");
            attr.setFieldMapping(fieldMappingWith(rdnField("1.2.840.113549.1.9.1")));

            UUID connectorUuid = connectorAuthority.getUuid();
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
        }

        @Test
        void testFieldMapping_sanField_missingGeneralNameType_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_san_no_type");
            SanMappedField san = new SanMappedField();
            san.setFieldType(FieldType.SAN);
            san.setGeneralNameType(null);
            attr.setFieldMapping(fieldMappingWith(san));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping SAN field is missing generalNameType"), ex::getMessage);
        }

        @Test
        void testFieldMapping_sanField_otherNameMissingOid_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_san_othername_no_oid");
            SanMappedField san = new SanMappedField();
            san.setFieldType(FieldType.SAN);
            san.setGeneralNameType(GeneralNameType.OTHER_NAME);
            san.setOtherNameOid(null);
            attr.setFieldMapping(fieldMappingWith(san));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("is missing otherNameOid or it is not a valid OID"), ex::getMessage);
        }

        @Test
        void testFieldMapping_sanField_otherNameNotOid_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_san_othername_not_oid");
            SanMappedField san = new SanMappedField();
            san.setFieldType(FieldType.SAN);
            san.setGeneralNameType(GeneralNameType.OTHER_NAME);
            san.setOtherNameOid("not an oid");
            attr.setFieldMapping(fieldMappingWith(san));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("is missing otherNameOid or it is not a valid OID"), ex::getMessage);
        }

        @Test
        void testFieldMapping_sanField_otherNameWithOid_ok() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_san_othername_with_oid");
            SanMappedField san = new SanMappedField();
            san.setFieldType(FieldType.SAN);
            san.setGeneralNameType(GeneralNameType.OTHER_NAME);
            san.setOtherNameOid("1.2.3.4");
            attr.setFieldMapping(fieldMappingWith(san));

            UUID connectorUuid = connectorAuthority.getUuid();
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
        }

        @Test
        void testFieldMapping_sanField_dns_ok() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_san_dns");
            SanMappedField san = new SanMappedField();
            san.setFieldType(FieldType.SAN);
            san.setGeneralNameType(GeneralNameType.DNS);
            attr.setFieldMapping(fieldMappingWith(san));

            UUID connectorUuid = connectorAuthority.getUuid();
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
        }

        @Test
        void testFieldMapping_extensionField_missingOid_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_ext_no_oid");
            ExtensionMappedField ext = new ExtensionMappedField();
            ext.setFieldType(FieldType.EXTENSION);
            ext.setExtensionOid(null);
            attr.setFieldMapping(fieldMappingWith(ext));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping EXTENSION field is missing extensionOid"), ex::getMessage);
        }

        @Test
        void testFieldMapping_extensionField_unregisteredOid_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_ext_unreg_oid");
            ExtensionMappedField ext = new ExtensionMappedField();
            ext.setFieldType(FieldType.EXTENSION);
            ext.setExtensionOid("9.9.9.99");
            attr.setFieldMapping(fieldMappingWith(ext));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("is not registered in the OID registry"), ex::getMessage);
        }

        @Test
        void testFieldMapping_extensionField_duplicateOidInOneMapping_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_ext_dup_oid");
            attr.setFieldMapping(fieldMappingWith(extensionField(REGISTERED_EXTENSION_OID), extensionField(REGISTERED_EXTENSION_OID)));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains(REGISTERED_EXTENSION_OID)
                    && ex.getMessage().contains("more than once"), ex::getMessage);
        }

        @Test
        void testFieldMapping_extensionField_registeredOid_ok() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_ext_reg_oid");
            ExtensionMappedField ext = new ExtensionMappedField();
            ext.setFieldType(FieldType.EXTENSION);
            ext.setExtensionOid(REGISTERED_EXTENSION_OID);
            attr.setFieldMapping(fieldMappingWith(ext));

            UUID connectorUuid = connectorAuthority.getUuid();
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
        }

        // ── contentType must be STRING for fieldMapping attributes ────────────────

        @Test
        void testFieldMapping_nonStringContentType_throws() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_integer");
            attr.setContentType(AttributeContentType.INTEGER);
            attr.setFieldMapping(fieldMappingWith(rdnField("CN")));

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping is only valid for attributes with STRING or TEXT content type"), ex::getMessage);
        }

        // ── isRequestOperation gating ─────────────────────────────────────────────

        @Test
        void testFieldMapping_nonRequestOperation_skipsValidation() {
            // Invalid fieldMapping (no objectType) should NOT throw when operation is not a request operation
            DataAttributeV3 attr = fieldMappingAttribute("fm_non_req_op");
            FieldMapping fm = new FieldMapping();
            fm.setObjectType(null);
            fm.setFields(List.of());
            attr.setFieldMapping(fm);

            UUID connectorUuid = connectorAuthority.getUuid();
            // null operation → skips validateFieldMapping, so no exception
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(attr)));
        }

        @Test
        void testFieldMapping_signOperation_validatesFieldMapping() {
            DataAttributeV3 attr = fieldMappingAttribute("fm_sign_op");
            FieldMapping fm = new FieldMapping();
            fm.setObjectType(null);
            fm.setFields(List.of(rdnField("CN")));
            attr.setFieldMapping(fm);

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, AttributeOperation.SIGN, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("fieldMapping.objectType is required"), ex::getMessage);
        }

        // ── validateResourceAttributeProperties relaxation ───────────────────────

        @Test
        void testResourceAttribute_withStaticListValueSource_noCallbackRequired() {
            DataAttributeV3 attr = new DataAttributeV3();
            attr.setUuid(UUID.randomUUID().toString());
            attr.setName("fm_static_list_resource");
            attr.setType(AttributeType.DATA);
            attr.setContentType(AttributeContentType.RESOURCE);
            DataAttributeProperties props = new DataAttributeProperties();
            props.setLabel("Resource Attr");
            props.setResource(AttributeResource.AUTHORITY);
            attr.setProperties(props);

            ValueSource valueSource = new ValueSource();
            valueSource.setKind(ValueSourceType.STATIC_LIST);
            attr.setValueSource(valueSource);

            UUID connectorUuid = connectorAuthority.getUuid();
            Assertions.assertDoesNotThrow(
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(attr)));
        }

        @Test
        void testResourceAttribute_withNoneValueSource_callbackRequired() {
            DataAttributeV3 attr = new DataAttributeV3();
            attr.setUuid(UUID.randomUUID().toString());
            attr.setName("fm_none_src_resource");
            attr.setType(AttributeType.DATA);
            attr.setContentType(AttributeContentType.RESOURCE);
            DataAttributeProperties props = new DataAttributeProperties();
            props.setLabel("Resource Attr");
            props.setResource(AttributeResource.AUTHORITY);
            attr.setProperties(props);

            ValueSource valueSource = new ValueSource();
            valueSource.setKind(ValueSourceType.NONE);
            attr.setValueSource(valueSource);

            UUID connectorUuid = connectorAuthority.getUuid();
            AttributeException ex = Assertions.assertThrows(AttributeException.class,
                    () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(attr)));
            Assertions.assertTrue(ex.getMessage().contains("missing callback"), ex::getMessage);
        }

        // ── helpers ───────────────────────────────────────────────────────────────

        private DataAttributeV3 fieldMappingAttribute(String name) {
            DataAttributeV3 attr = new DataAttributeV3();
            attr.setUuid(UUID.randomUUID().toString());
            attr.setName(name);
            attr.setType(AttributeType.DATA);
            attr.setContentType(AttributeContentType.STRING);
            DataAttributeProperties props = new DataAttributeProperties();
            props.setLabel(name);
            attr.setProperties(props);
            return attr;
        }

        private FieldMapping fieldMappingWith(MappedField... fields) {
            FieldMapping fm = new FieldMapping();
            fm.setObjectType(ObjectType.X509_CERTIFICATE);
            fm.setFields(List.of(fields));
            return fm;
        }

        private RdnMappedField rdnField(String rdn) {
            RdnMappedField f = new RdnMappedField();
            f.setFieldType(FieldType.RDN);
            f.setRdn(rdn);
            return f;
        }

        private ExtensionMappedField extensionField(String extensionOid) {
            ExtensionMappedField f = new ExtensionMappedField();
            f.setFieldType(FieldType.EXTENSION);
            f.setExtensionOid(extensionOid);
            return f;
        }
    }
}
