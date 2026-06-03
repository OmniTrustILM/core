package com.czertainly.core.service.compliance;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.compliance.*;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.connector.compliance.ComplianceRequestRulesDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.compliance.ComplianceProfileDto;
import com.czertainly.api.model.core.compliance.ComplianceProfilesListDto;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ComplianceProfileExternalService;
import com.czertainly.core.service.ComplianceProfileInternalService;
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

class ComplianceProfileServiceTest extends BaseSpringBootTest {

    private static final String KIND = "default";

    @Autowired
    private ComplianceProfileRepository complianceProfileRepository;

    @Autowired
    private ComplianceProfileExternalService complianceProfileService;
    @Autowired
    private ComplianceProfileInternalService complianceProfileInternalService;

    @Autowired
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;

    @Autowired
    private ComplianceProfileAssociationRepository complianceProfileAssociationRepository;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;

    private Connector connector;
    private WireMockServer mockServer;
    private ComplianceProfile complianceProfile;

    private UUID associatedRaProfileUuid;
    private UUID unassociatedRaProfileUuid;

    private final UUID complianceRuleUuid = UUID.randomUUID();
    private final UUID complianceRule2Uuid = UUID.randomUUID();
    private final UUID complianceGroupUuid = UUID.randomUUID();
    private final UUID complianceGroup2Uuid = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        mockComplianceProvider();

        connector = new Connector();
        connector.setName("Sample Connector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.COMPLIANCE_PROVIDER);
        functionGroup.setName(FunctionGroupCode.COMPLIANCE_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of(KIND)));
        connector2FunctionGroupRepository.save(c2fg);
        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        complianceProfile = new ComplianceProfile();
        complianceProfile.setName("TestProfile");
        complianceProfile.setDescription("Sample Description");
        complianceProfileRepository.save(complianceProfile);

        var complianceProfileRule = new ComplianceProfileRule();
        complianceProfileRule.setComplianceProfile(complianceProfile);
        complianceProfileRule.setComplianceProfileUuid(complianceProfile.getUuid());
        complianceProfileRule.setResource(Resource.CERTIFICATE);
        complianceProfileRule.setConnectorUuid(connector.getUuid());
        complianceProfileRule.setKind(KIND);
        complianceProfileRule.setComplianceRuleUuid(complianceRuleUuid);
        complianceProfileRuleRepository.save(complianceProfileRule);

        ComplianceProfileRule complianceProfileRule2 = new ComplianceProfileRule();
        complianceProfileRule2.setComplianceProfile(complianceProfile);
        complianceProfileRule2.setComplianceProfileUuid(complianceProfile.getUuid());
        complianceProfileRule2.setResource(Resource.CERTIFICATE);
        complianceProfileRule2.setConnectorUuid(connector.getUuid());
        complianceProfileRule2.setKind(KIND);
        complianceProfileRule2.setComplianceGroupUuid(complianceGroupUuid);
        complianceProfileRuleRepository.save(complianceProfileRule2);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("TestProfile");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);
        associatedRaProfileUuid = raProfile.getUuid();

        ComplianceProfileAssociation complianceProfileAssociation = new ComplianceProfileAssociation();
        complianceProfileAssociation.setComplianceProfileUuid(complianceProfile.getUuid());
        complianceProfileAssociation.setResource(Resource.RA_PROFILE);
        complianceProfileAssociation.setObjectUuid(raProfile.getUuid());
        complianceProfileAssociationRepository.save(complianceProfileAssociation);

        raProfile = new RaProfile();
        raProfile.setName("TestProfile2");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);
        unassociatedRaProfileUuid = raProfile.getUuid();

        complianceProfile = complianceProfileRepository.findWithAssociationsByUuid(complianceProfile.getUuid()).orElseThrow();
        Assertions.assertFalse(complianceProfile.getComplianceRules().isEmpty(), "Compliance rules should be loaded");
        Assertions.assertFalse(complianceProfile.getAssociations().isEmpty(), "Compliance associations should be loaded");
    }

    private void mockComplianceProvider() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/v1/complianceProvider/%s/rules".formatted(KIND)))
                .willReturn(WireMock.aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                [
                                  {
                                    "uuid": "%s",
                                    "name": "Rule1",
                                    "description": "Description",
                                    "certificateType": "X.509"
                                  },
                                  {
                                    "uuid": "%s",
                                    "name": "Rule2",
                                    "description": "Description2",
                                    "groupUuid": "%s",
                                    "certificateType": "X.509",
                                    "attributes": []
                                  }
                                ]
                                """.formatted(complianceRuleUuid, complianceRule2Uuid, complianceGroup2Uuid))
                        .withStatus(200)));
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/v1/complianceProvider/%s/groups".formatted(KIND)))
                .willReturn(WireMock.aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                [
                                  {
                                    "uuid": "%s",
                                    "name": "Group1",
                                    "description": "Sample description"
                                  },
                                  {
                                    "uuid": "%s",
                                    "name": "Group2",
                                    "description": "Sample description"
                                  }
                                ]
                                """.formatted(complianceGroupUuid, complianceGroup2Uuid))
                        .withStatus(200)));
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testResourceObjectsHandling() throws NotFoundException {
        var complianceProfile2 = new ComplianceProfile();
        complianceProfile2.setName("TestProfile2");
        complianceProfile2.setDescription("Sample Description2");
        complianceProfileRepository.save(complianceProfile2);

        var objects = complianceProfileInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(2, objects.size());

        var profileInfo = complianceProfileInternalService.getResourceObjectInternal(complianceProfile.getUuid());
        Assertions.assertEquals(complianceProfile.getName(), profileInfo.getName());
    }

    @Test
    void testListComplianceProfiles() {
        List<ComplianceProfilesListDto> dtos = complianceProfileService.listComplianceProfiles(SecurityFilter.create());
        Assertions.assertNotNull(dtos);
        Assertions.assertEquals(1, dtos.size());
        Assertions.assertEquals("TestProfile", dtos.getFirst().getName());
        Assertions.assertEquals(complianceProfile.getUuid().toString(), dtos.getFirst().getUuid());
    }

    @Test
    void testGetComplianceProfile() throws NotFoundException, ConnectorException {
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertNotNull(complianceProfileDto);
        Assertions.assertEquals(complianceProfileDto.getName(), complianceProfile.getName());
        Assertions.assertEquals(complianceProfileDto.getUuid(), complianceProfile.getUuid().toString());
        Assertions.assertEquals(complianceProfileDto.getDescription(), complianceProfile.getDescription());
        Assertions.assertEquals(complianceProfileDto.getRules().size(), complianceProfile.getComplianceRules().stream().filter(r -> r.getComplianceRuleUuid() != null).count());
        Assertions.assertEquals(complianceProfileDto.getGroups().size(), complianceProfile.getComplianceRules().stream().filter(r -> r.getComplianceGroupUuid() != null).count());
    }

    @Test
    void testGetComplianceProfileNotFound() {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void createComplianceProfileTest() throws AlreadyExistException, AttributeException, NotFoundException, ConnectorException {
        ComplianceProfileRequestDto requestDto = new ComplianceProfileRequestDto();
        requestDto.setName("sample2");
        requestDto.setDescription("sampleDescription");

        ComplianceProfileDto dto = complianceProfileService.createComplianceProfile(requestDto);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(0, dto.getRules().size());
        Assertions.assertEquals("sample2", dto.getName());
        Assertions.assertEquals("sampleDescription", dto.getDescription());

        ComplianceProfileRulesRequestDto rulesRequestDto = new ComplianceProfileRulesRequestDto();
        rulesRequestDto.setConnectorUuid(connector.getUuid().toString());
        rulesRequestDto.setKind(KIND);

        ComplianceRequestRulesDto ruleRequesDto = new ComplianceRequestRulesDto();
        ruleRequesDto.setUuid(complianceRuleUuid.toString());
        rulesRequestDto.setRules(List.of(ruleRequesDto));
        rulesRequestDto.setGroups(List.of(complianceGroupUuid.toString()));

        requestDto.setName("SampleWithRules");
        requestDto.setRules(List.of(rulesRequestDto));
        dto = complianceProfileService.createComplianceProfile(requestDto);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(1, dto.getRules().size());
        Assertions.assertEquals(1, dto.getGroups().size());
        Assertions.assertEquals(1, dto.getRules().getFirst().getRules().size());
        Assertions.assertEquals(1, dto.getGroups().getFirst().getGroups().size());
    }

    @Test
    void createComplianceProfile_AlreadyExistsTest() {
        ComplianceProfileRequestDto requestDto = new ComplianceProfileRequestDto();
        requestDto.setName("TestProfile");
        requestDto.setDescription("description");

        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.createComplianceProfile(requestDto));
    }

    @Test
    void addRuleTest() throws NotFoundException, AlreadyExistException, ConnectorException {
        ComplianceRuleAdditionRequestDto dto = new ComplianceRuleAdditionRequestDto();
        dto.setRuleUuid(complianceRuleUuid.toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        ComplianceProfileRuleDto complianceProfileRuleDto = complianceProfileService.addRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileRuleDto);

        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getRules().size());
        Assertions.assertEquals(1, complianceProfileDto.getRules().getFirst().getRules().size());

        // add new group
        dto.setRuleUuid(complianceRule2Uuid.toString());
        complianceProfileRuleDto = complianceProfileService.addRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileRuleDto);

        complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getRules().size());
        Assertions.assertEquals(2, complianceProfileDto.getRules().getFirst().getRules().size());
    }

    @Test
    void addRule_RuleNotFound() {
        ComplianceRuleAdditionRequestDto dto = new ComplianceRuleAdditionRequestDto();
        dto.setRuleUuid(UUID.randomUUID().toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.addRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void deleteRuleTest() throws NotFoundException, ConnectorException {
        ComplianceRuleDeletionRequestDto dto = new ComplianceRuleDeletionRequestDto();
        dto.setRuleUuid(complianceRuleUuid.toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        ComplianceProfileRuleDto complianceProfileDto = complianceProfileService.removeRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
    }

    @Test
    void deleteRule_RuleNotFound() {
        ComplianceRuleDeletionRequestDto dto = new ComplianceRuleDeletionRequestDto();
        dto.setRuleUuid(UUID.randomUUID().toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.removeRule(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void addGroupTest() throws NotFoundException, AlreadyExistException, ConnectorException {
        // add group which is already in the profile
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid(complianceGroupUuid.toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        ComplianceProfileDto complianceProfileDto = complianceProfileService.addGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
        Assertions.assertEquals(1, complianceProfileDto.getGroups().size());
        Assertions.assertEquals(1, complianceProfileDto.getGroups().getFirst().getGroups().size());

        // add new group
        dto.setGroupUuid(complianceGroup2Uuid.toString());
        complianceProfileDto = complianceProfileService.addGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
        Assertions.assertEquals(1, complianceProfileDto.getGroups().size());
        Assertions.assertEquals(2, complianceProfileDto.getGroups().getFirst().getGroups().size());
    }

    @Test
    void addGroup_RuleNotFound() {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid(UUID.randomUUID().toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.addGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void deleteGroupTest() throws NotFoundException, ConnectorException {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid(complianceGroupUuid.toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        ComplianceProfileDto complianceProfileDto = complianceProfileService.removeGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        Assertions.assertNotNull(complianceProfileDto);
    }

    @Test
    void deleteGroup_RuleNotFound() {
        ComplianceGroupRequestDto dto = new ComplianceGroupRequestDto();
        dto.setGroupUuid(UUID.randomUUID().toString());
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setKind(KIND);

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.removeGroup(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void removeComplianceProfileTest() {
        SecuredUUID uuid = SecuredUUID.fromUUID(complianceProfile.getUuid());
        Assertions.assertThrows(ValidationException.class, () -> complianceProfileService.deleteComplianceProfile(uuid));
    }

    @Test
    void forceRemoveComplianceProfileTest() {
        complianceProfileService.forceDeleteComplianceProfiles(List.of(SecuredUUID.fromUUID(complianceProfile.getUuid())));
        Assertions.assertDoesNotThrow(() -> complianceProfileRepository.findAll().size());
    }

    @Test
    void removeComplianceProfile_NotFound() {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.deleteComplianceProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void getRaProfile() {
        List<SimplifiedRaProfileDto> ra = complianceProfileService.getAssociatedRAProfiles(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertNotNull(ra);
        Assertions.assertEquals(1, ra.size());
    }

    @Test
    void associateRaProfile() throws NotFoundException, ConnectorException, AlreadyExistException {
        RaProfileAssociationRequestDto request = new RaProfileAssociationRequestDto();
        request.setRaProfileUuids(List.of(associatedRaProfileUuid.toString()));
        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.associateProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), request));

        request.setRaProfileUuids(List.of(unassociatedRaProfileUuid.toString()));
        complianceProfileService.associateProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), request);
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(2, complianceProfileDto.getRaProfiles().size());
    }

    @Test
    void testDisassociateProfile() throws NotFoundException, ConnectorException {
        Certificate archivedCertificate = new Certificate();
        archivedCertificate.setArchived(true);
        archivedCertificate.setRaProfileUuid(associatedRaProfileUuid);
        archivedCertificate.setComplianceStatus(ComplianceStatus.OK);
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("c");
        certificateContentRepository.save(certificateContent);
        archivedCertificate.setCertificateContent(certificateContent);
        certificateRepository.save(archivedCertificate);
        Certificate notArchivedCertificate = new Certificate();
        notArchivedCertificate.setRaProfileUuid(associatedRaProfileUuid);
        notArchivedCertificate.setComplianceStatus(ComplianceStatus.OK);
        CertificateContent certificateContent2 = new CertificateContent();
        certificateContent2.setContent("c2");
        certificateContentRepository.save(certificateContent2);
        notArchivedCertificate.setCertificateContent(certificateContent2);
        certificateRepository.save(notArchivedCertificate);

        RaProfileAssociationRequestDto request = new RaProfileAssociationRequestDto();
        request.setRaProfileUuids(List.of(unassociatedRaProfileUuid.toString()));
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.disassociateProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), request));

        request.setRaProfileUuids(List.of(associatedRaProfileUuid.toString()));
        complianceProfileService.disassociateProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), request);

        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(0, complianceProfileDto.getRaProfiles().size());

        // later when compliance check is redone, the status will be set to NOT_CHECKED and assertion will pass
    }

    @Test
    void getComplianceRulesTest_Invalid() {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceRules("abfbc322-29e1-11ed-a261-0242ac120002", null, null));
    }

    @Test
    void getComplianceRulesTest() throws ConnectorException, NotFoundException {
        var rules = complianceProfileService.getComplianceRules(connector.getUuid().toString(), KIND, null);
        Assertions.assertEquals(1, rules.size());
        Assertions.assertEquals(2, rules.getFirst().getRules().size());
    }

    @Test
    void getComplianceGroupsTest_Invalid() {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceGroups("abfbc322-29e1-11ed-a261-0242ac120002", null));
    }

    @Test
    void getComplianceGroupsTest() throws ConnectorException, NotFoundException {
        var groups = complianceProfileService.getComplianceGroups(connector.getUuid().toString(), KIND);
        Assertions.assertEquals(1, groups.size());
        Assertions.assertEquals(2, groups.getFirst().getGroups().size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = complianceProfileInternalService.getResourceObjectInternal(complianceProfile.getUuid());
        Assertions.assertEquals(complianceProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(complianceProfile.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = complianceProfileInternalService.getResourceObjectExternal(complianceProfile.getSecuredUuid());
        Assertions.assertEquals(complianceProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(complianceProfile.getName(), nameAndUuidDto.getName());
    }
}
