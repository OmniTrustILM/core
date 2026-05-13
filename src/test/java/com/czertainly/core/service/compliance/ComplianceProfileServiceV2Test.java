package com.czertainly.core.service.compliance;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.compliance.v2.*;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.connector.compliance.v2.ComplianceRuleRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateSubjectType;
import com.czertainly.api.model.core.compliance.ComplianceRuleAvailabilityStatus;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceProfileDto;
import com.czertainly.api.model.core.compliance.v2.ComplianceProfileListDto;
import com.czertainly.api.model.core.compliance.v2.ComplianceRuleListDto;
import com.czertainly.api.model.core.compliance.v2.ProviderComplianceRulesDto;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.Set;
import java.util.UUID;

class ComplianceProfileServiceV2Test extends BaseComplianceTest {

    @Test
    void testResourceObjectsHandling() throws NotFoundException {
        var complianceProfile2 = new ComplianceProfile();
        complianceProfile2.setName("TestProfile2");
        complianceProfile2.setDescription("Sample Description2");
        complianceProfileRepository.save(complianceProfile2);

        var objects = complianceProfileService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(2, objects.size());

        var profileInfo = complianceProfileService.getResourceObjectInternal(complianceProfile.getUuid());
        Assertions.assertEquals(complianceProfile.getName(), profileInfo.getName());
    }

    @Test
    void testListComplianceProfiles() {
        List<ComplianceProfileListDto> dtos = complianceProfileService.listComplianceProfiles(SecurityFilter.create());
        Assertions.assertNotNull(dtos);
        Assertions.assertEquals(1, dtos.size());
        Assertions.assertEquals(complianceProfile.getName(), dtos.getFirst().getName());
        Assertions.assertEquals(complianceProfile.getUuid(), dtos.getFirst().getUuid());
        Assertions.assertEquals(2, dtos.getFirst().getInternalRulesCount());
        Assertions.assertEquals(1, dtos.getFirst().getProviderRulesCount());
        Assertions.assertEquals(1, dtos.getFirst().getProviderGroupsCount());
    }

    @Test
    void testGetComplianceProfile() throws NotFoundException, ConnectorException {
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertNotNull(complianceProfileDto);
        Assertions.assertEquals(complianceProfileDto.getName(), complianceProfile.getName());
        Assertions.assertEquals(complianceProfileDto.getUuid(), complianceProfile.getUuid());
        Assertions.assertEquals(complianceProfileDto.getDescription(), complianceProfile.getDescription());
        Assertions.assertEquals(complianceProfileDto.getInternalRules().size(), complianceProfile.getComplianceRules().stream().filter(r -> r.getInternalRuleUuid() != null).count());
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(complianceProfileDto.getProviderRules().getFirst().getRules().size(), complianceProfile.getComplianceRules().stream().filter(r -> r.getComplianceRuleUuid() != null).count());
        Assertions.assertEquals(complianceProfileDto.getProviderRules().getFirst().getGroups().size(), complianceProfile.getComplianceRules().stream().filter(r -> r.getComplianceGroupUuid() != null).count());
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
        Assertions.assertEquals(0, dto.getProviderRules().size());
        Assertions.assertEquals(0, dto.getInternalRules().size());
        Assertions.assertEquals("sample2", dto.getName());
        Assertions.assertEquals("sampleDescription", dto.getDescription());
    }

    @Test
    void createComplianceProfile_AlreadyExistsTest() {
        ComplianceProfileRequestDto requestDto = new ComplianceProfileRequestDto();
        requestDto.setName("TestProfile");
        requestDto.setDescription("description");

        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.createComplianceProfile(requestDto));
    }

    @Test
    void updateComplianceProfileTest() throws AttributeException, NotFoundException, ConnectorException {
        ComplianceProfileUpdateRequestDto requestDto = new ComplianceProfileUpdateRequestDto();
        requestDto.setDescription("sampleDescription2");
        requestDto.setInternalRules(Set.of(internalCertificateRuleUuid, internalCertificateRule2Uuid));

        ComplianceRuleRequestDto ruleRequestV1Dto = new ComplianceRuleRequestDto();
        ruleRequestV1Dto.setUuid(complianceV1RuleUuid);
        ComplianceRuleRequestDto ruleRequestV1Dto2 = new ComplianceRuleRequestDto();
        ruleRequestV1Dto2.setUuid(complianceV1Rule2Uuid);
        ComplianceRuleRequestDto ruleRequestV2Dto = new ComplianceRuleRequestDto();
        ruleRequestV2Dto.setUuid(complianceV2RuleUuid);
        ComplianceRuleRequestDto ruleRequestV2Dto2 = new ComplianceRuleRequestDto();
        ruleRequestV2Dto2.setUuid(complianceV2Rule2Uuid);

        ProviderComplianceRulesRequestDto providerRequestV1Dto = new ProviderComplianceRulesRequestDto();
        providerRequestV1Dto.setConnectorUuid(connectorV1.getUuid());
        providerRequestV1Dto.setKind(KIND_V1);
        providerRequestV1Dto.setRules(Set.of(ruleRequestV1Dto, ruleRequestV1Dto2));
        providerRequestV1Dto.setGroups(Set.of(complianceV1GroupUuid));
        requestDto.getProviderRules().add(providerRequestV1Dto);

        ProviderComplianceRulesRequestDto providerRequestV2Dto = new ProviderComplianceRulesRequestDto();
        providerRequestV2Dto.setConnectorUuid(connectorV2.getUuid());
        providerRequestV2Dto.setKind(KIND_V2);
        providerRequestV2Dto.setRules(Set.of(ruleRequestV2Dto, ruleRequestV2Dto2));
        providerRequestV2Dto.setGroups(Set.of(complianceV2GroupUuid, complianceV2Group2Uuid));
        requestDto.getProviderRules().add(providerRequestV2Dto);

        ComplianceProfileDto dto = complianceProfileService.updateComplianceProfile(complianceProfile.getSecuredUuid(), requestDto);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals("sampleDescription2", dto.getDescription());
        Assertions.assertEquals(2, dto.getInternalRules().size());
        Assertions.assertEquals(2, dto.getProviderRules().size());

        ProviderComplianceRulesDto providerRulesDtoV1 = dto.getProviderRules().stream().filter(p -> p.getKind().equals(KIND_V1)).findFirst().orElseThrow();
        ProviderComplianceRulesDto providerRulesDtoV2 = dto.getProviderRules().stream().filter(p -> p.getKind().equals(KIND_V2)).findFirst().orElseThrow();
        Assertions.assertEquals(2, providerRulesDtoV1.getRules().size());
        Assertions.assertEquals(1, providerRulesDtoV1.getGroups().size());
        Assertions.assertEquals(2, providerRulesDtoV2.getRules().size());
        Assertions.assertEquals(2, providerRulesDtoV2.getGroups().size());

        // test availability status, remove group and rule from the provider
        mockComplianceProviderResponses(false);

        dto = complianceProfileService.getComplianceProfile(complianceProfile.getSecuredUuid());
        Assertions.assertEquals(2, dto.getProviderRules().size());

        var providerRules = dto.getProviderRules().stream().filter(p -> p.getKind().equals(KIND_V2)).findFirst().orElseThrow();
        Assertions.assertEquals(2, providerRules.getRules().size());
        Assertions.assertEquals(2, providerRules.getGroups().size());
        Assertions.assertTrue(providerRules.getRules().stream().anyMatch(r -> r.getUuid().equals(complianceV2RuleUuid)));
        Assertions.assertEquals(ComplianceRuleAvailabilityStatus.NOT_AVAILABLE, providerRules.getRules().stream().filter(r -> r.getUuid().equals(complianceV2RuleUuid)).findFirst().orElseThrow().getAvailabilityStatus());
        Assertions.assertEquals(ComplianceRuleAvailabilityStatus.UPDATED, providerRules.getRules().stream().filter(r -> r.getUuid().equals(complianceV2Rule2Uuid)).findFirst().orElseThrow().getAvailabilityStatus());
        Assertions.assertTrue(providerRules.getGroups().stream().anyMatch(r -> r.getUuid().equals(complianceV2GroupUuid)));
        Assertions.assertEquals(ComplianceRuleAvailabilityStatus.NOT_AVAILABLE, providerRules.getGroups().stream().filter(r -> r.getUuid().equals(complianceV2GroupUuid)).findFirst().orElseThrow().getAvailabilityStatus());
        Assertions.assertEquals(ComplianceRuleAvailabilityStatus.UPDATED, providerRules.getGroups().stream().filter(r -> r.getUuid().equals(complianceV2Group2Uuid)).findFirst().orElseThrow().getAvailabilityStatus());
    }

    @Test
    void testCreateInternalRule() throws Exception {
        ConditionItemRequestDto conditionItemRequestDto = new ConditionItemRequestDto();
        conditionItemRequestDto.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequestDto.setFieldIdentifier(FilterField.SUBJECT_TYPE.name());
        conditionItemRequestDto.setOperator(FilterConditionOperator.EQUALS);
        conditionItemRequestDto.setValue(CertificateSubjectType.ROOT_CA.getCode());

        ComplianceInternalRuleRequestDto req = new ComplianceInternalRuleRequestDto();
        req.setName("TestInternalRule");
        req.setDescription("Description create");
        req.setResource(Resource.CERTIFICATE);
        req.setConditionItems(List.of(conditionItemRequestDto)); // no condition items
        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.createComplianceInternalRule(req));

        req.setName("TestInternalRule_Create");
        ComplianceRuleListDto created = complianceProfileService.createComplianceInternalRule(req);
        UUID createdUuid = created.getUuid();

        var opt = internalRuleRepository.findByUuid(createdUuid);
        Assertions.assertTrue(opt.isPresent(), "Internal rule must be persisted");
        ComplianceInternalRule entity = opt.get();
        Assertions.assertEquals("TestInternalRule_Create", entity.getName());
        Assertions.assertEquals("Description create", entity.getDescription());
        Assertions.assertEquals(Resource.CERTIFICATE, entity.getResource());
        Assertions.assertEquals(1, entity.getConditionItems().size());
        Assertions.assertEquals(FilterField.SUBJECT_TYPE.name(), entity.getConditionItems().stream().findFirst().orElseThrow().getFieldIdentifier());
    }

    @Test
    void testUpdateInternalRule() throws Exception {
        ConditionItemRequestDto conditionItemRequestDto = new ConditionItemRequestDto();
        conditionItemRequestDto.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequestDto.setFieldIdentifier(FilterField.SUBJECT_TYPE.name());
        conditionItemRequestDto.setOperator(FilterConditionOperator.EQUALS);
        conditionItemRequestDto.setValue(CertificateSubjectType.ROOT_CA.getCode());

        // create initial rule
        ComplianceInternalRuleRequestDto createReq = new ComplianceInternalRuleRequestDto();
        createReq.setName("TestInternalRule_Update");
        createReq.setDescription("Initial desc");
        createReq.setResource(Resource.CERTIFICATE);
        createReq.setConditionItems(List.of(conditionItemRequestDto));

        ComplianceRuleListDto created = complianceProfileService.createComplianceInternalRule(createReq);
        UUID uuid = created.getUuid();

        // prepare update
        conditionItemRequestDto.setValue(CertificateSubjectType.INTERMEDIATE_CA.getCode());
        ConditionItemRequestDto conditionItemRequestDto2 = new ConditionItemRequestDto();
        conditionItemRequestDto2.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequestDto2.setFieldIdentifier(FilterField.KEY_SIZE.name());
        conditionItemRequestDto2.setOperator(FilterConditionOperator.EQUALS);
        conditionItemRequestDto2.setValue(1024);

        ComplianceInternalRuleRequestDto updateReq = new ComplianceInternalRuleRequestDto();
        updateReq.setName("TestInternalRule_UpdatedName");
        updateReq.setDescription("Updated description");
        updateReq.setResource(Resource.CERTIFICATE);
        updateReq.setConditionItems(List.of(conditionItemRequestDto, conditionItemRequestDto2));

        complianceProfileService.updateComplianceInternalRule(uuid, updateReq);

        // verify persisted changes
        var opt = internalRuleRepository.findByUuid(uuid);
        Assertions.assertTrue(opt.isPresent(), "Updated internal rule must exist");
        ComplianceInternalRule entity = opt.get();
        Assertions.assertEquals("TestInternalRule_UpdatedName", entity.getName());
        Assertions.assertEquals("Updated description", entity.getDescription());
        Assertions.assertEquals(2, entity.getConditionItems().size());
        Assertions.assertEquals(FilterField.SUBJECT_TYPE.name(), entity.getConditionItems().stream().findFirst().orElseThrow().getFieldIdentifier());
    }

    @Test
    void testDeleteInternalRule() throws Exception {
        // delete associated internal rule
        Assertions.assertThrows(ValidationException.class, () -> complianceProfileService.deleteComplianceInternalRule(internalCertificateRuleUuid));

        // create rule to delete
        ComplianceInternalRuleRequestDto createReq = new ComplianceInternalRuleRequestDto();
        createReq.setName("TestInternalRule_Delete");
        createReq.setDescription("To be deleted");
        createReq.setResource(Resource.CERTIFICATE);
        createReq.setConditionItems(List.of());

        ComplianceRuleListDto created = complianceProfileService.createComplianceInternalRule(createReq);
        UUID uuid = created.getUuid();

        // delete
        complianceProfileService.deleteComplianceInternalRule(uuid);

        // verify removed
        var opt = internalRuleRepository.findByUuid(uuid);
        Assertions.assertTrue(opt.isEmpty(), "Internal rule should be removed after delete");
    }

    @Test
    void addRuleTest() throws NotFoundException, ConnectorException {
        ComplianceProfileRulesPatchRequestDto dto = new ComplianceProfileRulesPatchRequestDto();
        dto.setRemoval(false);
        dto.setRuleUuid(complianceV2RuleUuid);
        dto.setConnectorUuid(connectorV2.getUuid());
        dto.setKind(KIND_V2);

        complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().getFirst().getRules().size());

        // add new rule
        dto.setRuleUuid(complianceV2Rule2Uuid);
        complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);

        complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(2, complianceProfileDto.getProviderRules().getFirst().getRules().size());

        // add new rule V1
        dto.setRuleUuid(complianceV1RuleUuid);
        dto.setConnectorUuid(connectorV1.getUuid());
        dto.setKind(KIND_V1);
        complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);

        complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(2, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().stream().filter(r -> r.getKind().equals(KIND_V1)).findFirst().orElseThrow().getRules().size());
    }

    @Test
    void addRule_RuleNotFound() {
        ComplianceProfileRulesPatchRequestDto dto = new ComplianceProfileRulesPatchRequestDto();
        dto.setRemoval(false);
        dto.setRuleUuid(UUID.randomUUID());
        dto.setConnectorUuid(connectorV2.getUuid());
        dto.setKind(KIND_V2);

        Assertions.assertThrows(ConnectorEntityNotFoundException.class, () -> complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void deleteRuleTest() throws NotFoundException, ConnectorException {
        ComplianceProfileRulesPatchRequestDto dto = new ComplianceProfileRulesPatchRequestDto();
        dto.setRemoval(true);
        dto.setRuleUuid(internalCertificateRuleUuid);

        complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getInternalRules().size());
        Assertions.assertTrue(complianceProfileDto.getInternalRules().stream().noneMatch(r -> r.getUuid().equals(internalCertificateRuleUuid)));
    }

    @Test
    void deleteRule_RuleNotFound() {
        ComplianceProfileRulesPatchRequestDto dto = new ComplianceProfileRulesPatchRequestDto();
        dto.setRemoval(true);
        dto.setRuleUuid(UUID.randomUUID());

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void addGroupTest() throws NotFoundException, ConnectorException {
        // add group which is already in the profile
        ComplianceProfileGroupsPatchRequestDto dto = new ComplianceProfileGroupsPatchRequestDto();
        dto.setRemoval(false);
        dto.setGroupUuid(complianceV2GroupUuid);
        dto.setConnectorUuid(connectorV2.getUuid());
        dto.setKind(KIND_V2);

        complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().getFirst().getGroups().size());

        // add new group
        dto.setGroupUuid(complianceV2Group2Uuid);
        complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);

        complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(2, complianceProfileDto.getProviderRules().getFirst().getGroups().size());

        // add new rule V1
        dto.setGroupUuid(complianceV1GroupUuid);
        dto.setConnectorUuid(connectorV1.getUuid());
        dto.setKind(KIND_V1);
        complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);

        complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(2, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().stream().filter(r -> r.getKind().equals(KIND_V1)).findFirst().orElseThrow().getGroups().size());
    }

    @Test
    void addGroup_GroupNotFound() {
        ComplianceProfileGroupsPatchRequestDto dto = new ComplianceProfileGroupsPatchRequestDto();
        dto.setRemoval(false);
        dto.setGroupUuid(UUID.randomUUID());
        dto.setConnectorUuid(connectorV2.getUuid());
        dto.setKind(KIND_V2);

        Assertions.assertThrows(ConnectorEntityNotFoundException.class, () -> complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void deleteGroupTest() throws NotFoundException, ConnectorException {
        ComplianceProfileGroupsPatchRequestDto dto = new ComplianceProfileGroupsPatchRequestDto();
        dto.setRemoval(true);
        dto.setGroupUuid(complianceV2GroupUuid);
        dto.setConnectorUuid(connectorV2.getUuid());
        dto.setKind(KIND_V2);

        complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto);
        ComplianceProfileDto complianceProfileDto = complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, complianceProfileDto.getProviderRules().size());
        Assertions.assertEquals(0, complianceProfileDto.getProviderRules().getFirst().getGroups().size());
    }

    @Test
    void deleteGroup_GroupNotFound() {
        ComplianceProfileGroupsPatchRequestDto dto = new ComplianceProfileGroupsPatchRequestDto();
        dto.setRemoval(true);
        dto.setGroupUuid(UUID.randomUUID());
        dto.setConnectorUuid(connectorV2.getUuid());
        dto.setKind(KIND_V2);

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(complianceProfile.getUuid()), dto));
    }

    @Test
    void removeComplianceProfileTest() {
        SecuredUUID complianceProfileUuid = complianceProfile.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> complianceProfileService.deleteComplianceProfile(complianceProfileUuid));
    }

    @Test
    void testBulkDeleteComplianceProfiles() {
        // create profile that can be deleted
        ComplianceProfile profile1 = new ComplianceProfile();
        profile1.setName("BulkDeleteProfile1");
        profile1.setDescription("desc1");
        profile1 = complianceProfileRepository.save(profile1);

        // create profile that has an association -> deletion without force should fail
        ComplianceProfile profile2 = new ComplianceProfile();
        profile2.setName("BulkDeleteProfile2");
        profile2.setDescription("desc2");
        profile2 = complianceProfileRepository.save(profile2);

        ComplianceProfileAssociation assoc = new ComplianceProfileAssociation();
        assoc.setComplianceProfileUuid(profile2.getUuid());
        assoc.setResource(Resource.RA_PROFILE);
        assoc.setObjectUuid(UUID.randomUUID());
        complianceProfileAssociationRepository.save(assoc);

        // perform bulk delete
        List<SecuredUUID> uuids = List.of(SecuredUUID.fromUUID(profile1.getUuid()), SecuredUUID.fromUUID(profile2.getUuid()));
        List<BulkActionMessageDto> messages = complianceProfileService.bulkDeleteComplianceProfiles(uuids);

        // profile1 should be removed
        Assertions.assertFalse(complianceProfileRepository.findById(profile1.getUuid()).isPresent(), "Profile without associations should be deleted");

        // profile2 should remain and produce one failure message
        Assertions.assertTrue(complianceProfileRepository.findById(profile2.getUuid()).isPresent(), "Profile with association should not be deleted");
        Assertions.assertEquals(1, messages.size(), "One failure message expected for the profile that could not be deleted");
        Assertions.assertEquals(profile2.getUuid().toString(), messages.getFirst().getUuid(), "Failure message should reference the failing profile UUID");
        Assertions.assertNotNull(messages.getFirst().getMessage());
        Assertions.assertFalse(messages.getFirst().getMessage().isBlank());
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
    void getAssociations() throws NotFoundException {
        var associations = complianceProfileService.getAssociations(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(2, associations.size());
        Assertions.assertEquals(Resource.RA_PROFILE, associations.getFirst().getResource());
        Assertions.assertEquals(associatedRaProfileUuid, associations.getFirst().getObjectUuid());
        Assertions.assertEquals(Resource.VAULT_PROFILE, associations.get(1).getResource());
        Assertions.assertEquals(vaultProfileUuid, associations.get(1).getObjectUuid());

        var complianceProfiles = complianceProfileService.getAssociatedComplianceProfiles(Resource.RA_PROFILE, associatedRaProfileUuid);
        Assertions.assertEquals(1, complianceProfiles.size());
        Assertions.assertEquals(complianceProfile.getUuid(), complianceProfiles.getFirst().getUuid());
    }

    @Test
    void associateComplianceProfileRaProfileWithoutAuthorityRefSucceeds() throws AlreadyExistException, AttributeException, NotFoundException, ConnectorException {
        // External Authority "without CA" scenario: the RA Profile has no authorityInstanceReference.
        RaProfile externalRaProfile = new RaProfile();
        externalRaProfile.setName("ExternalWithoutCaRaProfile");
        externalRaProfile = raProfileRepository.save(externalRaProfile);

        ComplianceProfileRequestDto requestDto = new ComplianceProfileRequestDto();
        requestDto.setName("ExternalAuthorityComplianceProfile");
        ComplianceProfileDto profileDto = complianceProfileService.createComplianceProfile(requestDto);
        SecuredUUID profileUuid = SecuredUUID.fromUUID(profileDto.getUuid());

        UUID externalRaProfileUuid = externalRaProfile.getUuid();
        Assertions.assertDoesNotThrow(() -> complianceProfileService.associateComplianceProfile(profileUuid, Resource.RA_PROFILE, externalRaProfileUuid));

        var associations = complianceProfileService.getAssociations(profileUuid);
        Assertions.assertEquals(1, associations.size());
        Assertions.assertEquals(Resource.RA_PROFILE, associations.getFirst().getResource());
        Assertions.assertEquals(externalRaProfile.getUuid(), associations.getFirst().getObjectUuid());
    }

    @Test
    void associateRaProfile() throws NotFoundException, AlreadyExistException {
        Assertions.assertThrows(AlreadyExistException.class, () -> complianceProfileService.associateComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), Resource.RA_PROFILE, associatedRaProfileUuid));
        complianceProfileService.associateComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), Resource.RA_PROFILE, unassociatedRaProfileUuid);

        var associations = complianceProfileService.getAssociations(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(3, associations.size());
        Assertions.assertTrue(associations.stream().anyMatch(a -> a.getResource() == Resource.RA_PROFILE && a.getObjectUuid().equals(unassociatedRaProfileUuid)));
    }

    @Test
    void testDisassociateProfile() throws NotFoundException {
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

        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.disassociateComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), Resource.RA_PROFILE, unassociatedRaProfileUuid));
        complianceProfileService.disassociateComplianceProfile(SecuredUUID.fromUUID(complianceProfile.getUuid()), Resource.RA_PROFILE, associatedRaProfileUuid);

        var associations = complianceProfileService.getAssociations(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        Assertions.assertEquals(1, associations.size());
        Assertions.assertTrue(associations.stream().noneMatch(a -> a.getResource() == Resource.RA_PROFILE && a.getObjectUuid().equals(associatedRaProfileUuid)));

        // later when compliance check is redone, the status will be set to NOT_CHECKED and assertion will pass
    }

    @Test
    void getComplianceRulesTest_Invalid() {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceRules(UUID.randomUUID(), "random", null, null, null));
    }

    @Test
    void getComplianceRulesTest() throws ConnectorException, NotFoundException {
        var rules = complianceProfileService.getComplianceRules(null, null, null, null, null);
        Assertions.assertEquals(5, rules.size());

        rules = complianceProfileService.getComplianceRules(null, null, Resource.CERTIFICATE_REQUEST, null, null);
        Assertions.assertEquals(1, rules.size());

        rules = complianceProfileService.getComplianceRules(connectorV1.getUuid(), KIND_V1, null, null, null);
        Assertions.assertEquals(2, rules.size());

        rules = complianceProfileService.getComplianceRules(connectorV2.getUuid(), KIND_V2, null, null, null);
        Assertions.assertEquals(3, rules.size());
    }

    @Test
    void getComplianceGroupsTest_Invalid() {
        Assertions.assertThrows(NotFoundException.class, () -> complianceProfileService.getComplianceGroups(UUID.randomUUID(), null, null));
    }

    @Test
    void getComplianceGroupsTest() throws ConnectorException, NotFoundException {
        var groups = complianceProfileService.getComplianceGroups(connectorV1.getUuid(), KIND_V1, null);
        Assertions.assertEquals(1, groups.size());

        groups = complianceProfileService.getComplianceGroups(connectorV2.getUuid(), KIND_V2, null);
        Assertions.assertEquals(2, groups.size());
    }

    @Test
    void getComplianceGroupRulesTest() throws ConnectorException, NotFoundException {
        var groups = complianceProfileService.getComplianceGroupRules(complianceV2Group2Uuid, connectorV2.getUuid(), KIND_V2);
        Assertions.assertEquals(1, groups.size());
    }
}
