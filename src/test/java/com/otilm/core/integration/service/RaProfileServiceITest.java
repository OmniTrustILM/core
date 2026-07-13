package com.otilm.core.integration.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRelationDto;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.raprofile.*;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.ValueSourceType;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.api.model.core.raprofile.RaProfileDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesUpdateDto;
import com.otilm.api.model.core.raprofile.ValueSourceBindingDto;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.repository.*;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.ApprovalProfileData;
import com.otilm.core.service.ApprovalProfileExternalService;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.service.RaProfileInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

class RaProfileServiceITest extends ApprovalProfileData {

    private static final String RA_PROFILE_NAME = "testRaProfile1";

    @Autowired
    private RaProfileExternalService raProfileService;

    @Autowired
    private RaProfileInternalService raProfileInternalService;

    @Autowired
    private ApprovalProfileExternalService approvalProfileService;

    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private ScepProfileRepository scepProfileRepository;
    @Autowired
    private CmpProfileRepository cmpProfileRepository;

    @Autowired
    private ApprovalProfileRelationRepository approvalProfileRelationRepository;
    private RaProfile raProfile;
    private Certificate certificate;
    private CertificateContent certificateContent;
    private AuthorityInstanceReference authorityInstanceReference;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUuid(UUID.randomUUID());
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

        certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("123456789");
        certificate = certificateRepository.save(certificate);

        authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListRaProfiles() {
        List<RaProfileDto> raProfiles = raProfileService.listRaProfiles(SecurityFilter.create(), Optional.of(true));
        Assertions.assertNotNull(raProfiles);
        Assertions.assertFalse(raProfiles.isEmpty());
        Assertions.assertEquals(1, raProfiles.size());
        Assertions.assertEquals(raProfile.getUuid().toString(), raProfiles.get(0).getUuid());
    }

    @Test
    void testGetRaProfileByUuid() throws NotFoundException {
        RaProfileDto dto = raProfileService.getRaProfile(raProfile.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(raProfile.getUuid().toString(), dto.getUuid());
    }

    @Test
    void testGetRaProfileByUuid_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.getRaProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddRaProfile() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                .willReturn(WireMock.okJson("""
                        {
                            "certificates": [
                            ]
                        }""")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName("testRaProfile2");
        request.setAttributes(List.of());

        RaProfileDto dto = raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    void testAddRaProfile_connectorRejectsAttributes() {
        // v2 adapter path: the connector's RA-profile /validate returning false must surface as
        // ValidationException and abort the create before anything is persisted.
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("false")));

        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName("testRaProfileRejected");
        request.setAttributes(List.of());

        SecuredParentUUID authorityInstanceUuid = authorityInstanceReference.getSecuredParentUuid();
        Assertions.assertThrows(ValidationException.class, () -> raProfileService.addRaProfile(authorityInstanceUuid, request));
        Assertions.assertTrue(raProfileRepository.findByName("testRaProfileRejected").isEmpty());
    }

    @Test
    void testAddRaProfile_v3Authority() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        // v3 adapter path: definitions come from the stateless v3 endpoint and there is no
        // connector-side /validate round-trip at all.
        AuthorityFixtures.Fixture v3 = AuthorityFixtures.v3Authority(
                new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository,
                        raProfileRepository, connectorInterfaceRepository),
                mockServer);
        mockServer.stubFor(WireMock
                .any(WireMock.urlPathMatching("/v3/authorityProvider(/authorities)?/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));

        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName("testRaProfileV3");
        request.setAttributes(List.of());

        RaProfileDto dto = raProfileService.addRaProfile(v3.authority().getSecuredParentUuid(), request);

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.urlMatching(".*/validate")));
    }

    @Test
    void testAddRaProfile_validationFail() {
        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        SecuredParentUUID authorityInstanceUuid = authorityInstanceReference.getSecuredParentUuid();
        Assertions.assertThrows(ValidationException.class, () -> raProfileService.addRaProfile(authorityInstanceUuid, request));
    }

    @Test
    void testAddRaProfile_alreadyExist() {
        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName(RA_PROFILE_NAME); // raProfile with same username exist

        Assertions.assertThrows(AlreadyExistException.class, () -> raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    void testEditRaProfile() throws ConnectorException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        EditRaProfileRequestDto request = new EditRaProfileRequestDto();
        request.setDescription("some description");
        request.setAttributes(List.of());

        RaProfileDto dto = raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    void testEditRaProfile_notFound() {
        EditRaProfileRequestDto request = new EditRaProfileRequestDto();

        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    void testUpdateRaProfileValidation() throws NotFoundException {
        RaProfileCertificateValidationSettingsUpdateDto updateDto = new RaProfileCertificateValidationSettingsUpdateDto();
        updateDto.setEnabled(true);
        updateDto.setFrequency(10);
        updateDto.setExpiringThreshold(5);
        RaProfileDto raProfileDto = raProfileService.updateRaProfileValidationConfiguration(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(), raProfile.getSecuredUuid(), updateDto);
        Assertions.assertEquals(updateDto.getEnabled(), raProfileDto.getCertificateValidationSettings().getEnabled());
        Assertions.assertEquals(updateDto.getFrequency(), raProfileDto.getCertificateValidationSettings().getFrequency());
        Assertions.assertEquals(updateDto.getExpiringThreshold(), raProfileDto.getCertificateValidationSettings().getExpiringThreshold());

        RaProfileCertificateValidationSettingsUpdateDto updateDtoDefault = new RaProfileCertificateValidationSettingsUpdateDto();
        updateDtoDefault.setEnabled(true);
        raProfileDto = raProfileService.updateRaProfileValidationConfiguration(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(), raProfile.getSecuredUuid(), updateDtoDefault);
        Assertions.assertEquals(updateDto.getEnabled(), raProfileDto.getCertificateValidationSettings().getEnabled());
        Assertions.assertEquals(1, raProfileDto.getCertificateValidationSettings().getFrequency());
        Assertions.assertEquals(30, raProfileDto.getCertificateValidationSettings().getExpiringThreshold());

        updateDto.setEnabled(false);
        raProfileDto = raProfileService.updateRaProfileValidationConfiguration(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(), raProfile.getSecuredUuid(), updateDto);
        Assertions.assertEquals(updateDto.getEnabled(), raProfileDto.getCertificateValidationSettings().getEnabled());
        Assertions.assertNull(raProfileDto.getCertificateValidationSettings().getFrequency());
        Assertions.assertNull(raProfileDto.getCertificateValidationSettings().getExpiringThreshold());


    }

    @Test
    void testUpdateRaProfileRequestAttributes() throws NotFoundException {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid("ra-attr-1");
        definition.setName("server");
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Server");
        definition.setProperties(properties);

        ValueSourceBindingDto binding = new ValueSourceBindingDto();
        binding.setAttributeUuid("ra-attr-1");
        binding.setValueSourceType(ValueSourceType.STATIC_LIST);
        binding.setCollectionRef("cmdb.servers");

        RaProfileCertificateRequestAttributesUpdateDto updateDto = new RaProfileCertificateRequestAttributesUpdateDto();
        updateDto.setRequestAttributes(List.of(definition));
        updateDto.setMergeMode(AttributeSetMergeMode.MERGE);
        updateDto.setExternalCsrValidationStrict(Boolean.TRUE);
        updateDto.setValueSourceBindings(List.of(binding));

        RaProfileDto updated = raProfileService.updateRaProfileRequestAttributesConfiguration(
                raProfile.getAuthorityInstanceReference().getSecuredParentUuid(), raProfile.getSecuredUuid(), updateDto);

        Assertions.assertNotNull(updated.getCertificateRequestAttributes());
        Assertions.assertEquals(1, updated.getCertificateRequestAttributes().getRequestAttributes().size());
        Assertions.assertEquals(AttributeSetMergeMode.MERGE, updated.getCertificateRequestAttributes().getMergeMode());
        Assertions.assertEquals(Boolean.TRUE, updated.getCertificateRequestAttributes().getExternalCsrValidationStrict());
        Assertions.assertEquals(1, updated.getCertificateRequestAttributes().getValueSourceBindings().size());

        // the configuration is embedded on the detail view too
        RaProfileDto detail = raProfileService.getRaProfile(raProfile.getSecuredUuid());
        Assertions.assertEquals(1, detail.getCertificateRequestAttributes().getRequestAttributes().size());
        Assertions.assertEquals("server", detail.getCertificateRequestAttributes().getRequestAttributes().get(0).getName());
    }

    @Test
    void testRemoveRaProfile() throws NotFoundException {
        raProfileService.deleteRaProfile(raProfile.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.getRaProfile(raProfile.getSecuredUuid()));
    }

    @Test
    void testRemoveRaProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.deleteRaProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testEnableRaProfile() throws NotFoundException {
        raProfileService.enableRaProfile(raProfile.getSecuredParentUuid(), raProfile.getSecuredUuid());
        Assertions.assertEquals(true, raProfile.getEnabled());
    }

    @Test
    void testEnableRaProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.enableRaProfile(raProfile.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableRaProfile() throws NotFoundException {
        raProfileService.disableRaProfile(raProfile.getSecuredParentUuid(), raProfile.getSecuredUuid());
        Assertions.assertFalse(raProfileService.getRaProfile(raProfile.getSecuredUuid()).getEnabled());
    }

    @Test
    void testDisableRaProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.disableRaProfile(raProfile.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }


    @Test
    void testBulkRemove() {
        raProfileService.bulkDeleteRaProfile(List.of(raProfile.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> raProfileService.getRaProfile(raProfile.getSecuredUuid()));
    }

    @Test
    void testBulkEnable() {
        raProfileService.bulkEnableRaProfile(List.of(raProfile.getSecuredUuid()));
        Assertions.assertTrue(raProfile.getEnabled());
    }

    @Test
    void testBulkDisable() throws NotFoundException {
        raProfileService.bulkDisableRaProfile(List.of(raProfile.getSecuredUuid()));
        Assertions.assertFalse(raProfileService.getRaProfile(raProfile.getSecuredUuid()).getEnabled());
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = raProfileInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testAssociationRaProfileWithApprovalProfile() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileRelationDto approvalProfileRelation = raProfileService.associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());

        Assertions.assertNotNull(approvalProfileRelation);
        Assertions.assertEquals(raProfile.getUuid(), approvalProfileRelation.getResourceUuid());
        Assertions.assertEquals(approvalProfile.getUuid().toString(), approvalProfileRelation.getApprovalProfileUuid());
        Assertions.assertEquals(Resource.RA_PROFILE, approvalProfileRelation.getResource());
    }

    @Test
    void testDisassociationRaProfileWithApprovalProfile() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileRelationDto approvalProfileRelation = raProfileService.associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());
        Assertions.assertNotNull(approvalProfileRelation);

        raProfileService.disassociateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());

        final Optional<ApprovalProfileRelation> approvalProfileRelationOptional = approvalProfileRelationRepository.findByUuid(SecuredUUID.fromString(approvalProfileRelation.getUuid()));
        Assertions.assertFalse(approvalProfileRelationOptional.isPresent());
    }

    @Test
    void testListOfApprovalProfilesByRAProfile() throws NotFoundException, AlreadyExistException {
        final SecurityFilter securityFilter = SecurityFilter.create();
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileRelationDto approvalProfileRelation = raProfileService.associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());
        Assertions.assertNotNull(approvalProfileRelation);

        final List<ApprovalProfileDto> approvalProfiles = raProfileService.getAssociatedApprovalProfiles(raProfile.getAuthorityInstanceReferenceUuid().toString(), raProfile.getUuid().toString(), securityFilter);

        Assertions.assertEquals(1, approvalProfiles.size());

        final ApprovalProfileDto approvalProfileDto = approvalProfiles.get(0);
        Assertions.assertEquals(approvalProfile.getUuid().toString(), approvalProfileDto.getUuid());
    }

    @Test
    void testGetAuthorityCertificateChain() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                .willReturn(WireMock.okJson("""
                        {
                            "certificates": [
                                {
                                    "certificateData": "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",
                                    "uuid": null,
                                    "meta": null,
                                    "certificateType": "X.509"
                                }    ]
                        }""")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        EditRaProfileRequestDto request = new EditRaProfileRequestDto();
        request.setDescription("some description");
        request.setAttributes(List.of());
        raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request);

        RaProfile refreshedRaProfile = raProfileRepository.findByUuid(raProfile.getUuid()).orElse(null);
        Assertions.assertNotNull(refreshedRaProfile);
        Assertions.assertNotNull(refreshedRaProfile.getAuthorityCertificateUuid());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                .willReturn(WireMock.okJson("""
                        {
                            "certificates": [
                            ]
                        }""")));
        raProfileService.editRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request);

        refreshedRaProfile = raProfileRepository.findByUuid(raProfile.getUuid()).orElse(null);
        Assertions.assertNotNull(refreshedRaProfile);
        Assertions.assertNull(refreshedRaProfile.getAuthorityCertificateUuid());

        AddRaProfileRequestDto requestAdd = new AddRaProfileRequestDto();
        requestAdd.setName("testRaProfile2");
        requestAdd.setAttributes(List.of());
        RaProfileDto dto = raProfileService.addRaProfile(authorityInstanceReference.getSecuredParentUuid(), requestAdd);
        Assertions.assertEquals(refreshedRaProfile.getAuthorityCertificateUuid(), raProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).get().getAuthorityCertificateUuid());
    }

    @Test
    void testListIssueCertificateAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("""
                        []""")));

        List<BaseAttribute> attributes = raProfileService.listIssueCertificateAttributes(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid());
        Assertions.assertNotNull(attributes);
    }

    @Test
    void testActivateAcme() throws ConnectorException, NotFoundException, AttributeException {
        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfileRepository.save(acmeProfile);
        CmpProfile cmpProfile = new CmpProfile();
        cmpProfileRepository.save(cmpProfile);
        ScepProfile scepProfile = new ScepProfile();
        scepProfileRepository.save(scepProfile);

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes"))
                .willReturn(WireMock.okJson("[]")));
        UUID uuid = UUID.randomUUID();

        DataAttributeV2 dataAttributeV2 = new DataAttributeV2();
        dataAttributeV2.setUuid(uuid.toString());
        dataAttributeV2.setName("name");
        dataAttributeV2.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("label");
        dataAttributeV2.setProperties(properties);
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson(AttributeDefinitionUtils.serialize(List.of(dataAttributeV2)))));
        RequestAttributeV2 requestAttributeV2 = new RequestAttributeV2(uuid, dataAttributeV2.getName(), AttributeContentType.STRING, List.of(new StringAttributeContentV2("data")), AttributeVersion.V2);

        ActivateAcmeForRaProfileRequestDto request = new ActivateAcmeForRaProfileRequestDto();
        request.setIssueCertificateAttributes(List.of(requestAttributeV2));
        request.setRevokeCertificateAttributes(List.of());
        RaProfileAcmeDetailResponseDto response = raProfileService.activateAcmeForRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), acmeProfile.getSecuredUuid(), request);
        Assertions.assertEquals(requestAttributeV2.getContent().getFirst().getData(), ((List<BaseAttributeContentV2>)response.getIssueCertificateAttributes().getFirst().getContent()).getFirst().getData());

        ActivateScepForRaProfileRequestDto requestScep = new ActivateScepForRaProfileRequestDto();
        requestScep.setIssueCertificateAttributes(List.of(requestAttributeV2));
        RaProfileScepDetailResponseDto responseScep = raProfileService.activateScepForRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), scepProfile.getSecuredUuid(), requestScep);
        Assertions.assertEquals(requestAttributeV2.getContent().getFirst().getData(), ((List<BaseAttributeContentV2>)responseScep.getIssueCertificateAttributes().getFirst().getContent()).getFirst().getData());

        ActivateCmpForRaProfileRequestDto requestCmp = new ActivateCmpForRaProfileRequestDto();
        requestCmp.setIssueCertificateAttributes(List.of(requestAttributeV2));
        requestCmp.setRevokeCertificateAttributes(List.of());
        RaProfileCmpDetailResponseDto responseCmp = raProfileService.activateCmpForRaProfile(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), cmpProfile.getSecuredUuid(), requestCmp);
        Assertions.assertEquals(requestAttributeV2.getContent().getFirst().getData(), ((List<BaseAttributeContentV2>)responseCmp.getIssueCertificateAttributes().getFirst().getContent()).getFirst().getData());
    }

}
