package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDetailDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.*;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

class ApprovalProfileServiceTest extends ApprovalProfileData {

    @Autowired
    private ApprovalInternalService approvalInternalService;

    @Autowired
    private ApprovalProfileExternalService approvalProfileService;

    @Autowired
    private ApprovalProfileRepository approvalProfileRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;


    @Test
    void testCreationOfApprovalProfile() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);

        final Optional<ApprovalProfile> approvalProfileOptional = approvalProfileRepository.findWithVersionsByUuid(approvalProfile.getUuid());
        Assertions.assertTrue(approvalProfileOptional.isPresent());

        final ApprovalProfile approvalProfileDB = approvalProfileOptional.get();
        Assertions.assertEquals(1, approvalProfileDB.getApprovalProfileVersions().size());

        final ApprovalProfileDetailDto approvalProfileVersion = approvalProfileService.getApprovalProfile(approvalProfile.getSecuredUuid(), null);
        Assertions.assertEquals(1, approvalProfileVersion.getVersion());
        Assertions.assertEquals(10, approvalProfileVersion.getExpiry());
        Assertions.assertEquals(2, approvalProfileVersion.getApprovalSteps().size());
    }

    @Test
    void testEditApprovalProfile() throws NotFoundException, AlreadyExistException {
        ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        approvalProfile = approvalProfileService.editApprovalProfile(approvalProfile.getSecuredUuid(), approvalProfileUpdateRequestDto);

        approvalProfileUpdateRequestDto.setExpiry(24);

        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
        approvalProfile = approvalProfileService.editApprovalProfile(approvalProfile.getSecuredUuid(), approvalProfileUpdateRequestDto);

        final Optional<ApprovalProfile> approvalProfileOptional = approvalProfileRepository.findWithVersionsByUuid(approvalProfile.getUuid());
        Assertions.assertTrue(approvalProfileOptional.isPresent());

        final ApprovalProfile approvalProfileDB = approvalProfileOptional.get();

        Assertions.assertEquals(2, approvalProfileDB.getApprovalProfileVersions().size());

        final ApprovalProfileDetailDto approvalProfileVersion = approvalProfileService.getApprovalProfile(approvalProfile.getSecuredUuid(), null);
        Assertions.assertEquals(2, approvalProfileVersion.getVersion());
        Assertions.assertEquals(24, approvalProfileVersion.getExpiry());
        Assertions.assertEquals(3, approvalProfileVersion.getApprovalSteps().size());
    }

    @Test
    void testDeleteApprovalProfile() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        approvalProfileService.deleteApprovalProfile(approvalProfile.getSecuredUuid());

        final Optional<ApprovalProfile> approvalProfileDBOptional = approvalProfileRepository.findByUuid(SecuredUUID.fromUUID(approvalProfile.getUuid()));
        Assertions.assertFalse(approvalProfileDBOptional.isPresent());
    }

    @Test
    void testListApprovalProfiles() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        approvalProfileService.editApprovalProfile(approvalProfile.getSecuredUuid(), approvalProfileUpdateRequestDto);
        approvalProfileService.editApprovalProfile(approvalProfile.getSecuredUuid(), approvalProfileUpdateRequestDto);

        ApprovalProfileResponseDto approvalProfileResponseDto = approvalProfileService.listApprovalProfiles(SecurityFilter.create(), new PaginationRequestDto());
        Assertions.assertEquals(1, approvalProfileResponseDto.getApprovalProfiles().size());
    }

    @Test
    void testListApprovalProfileDetail() throws NotFoundException, AlreadyExistException {
        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        final ApprovalProfileDetailDto approvalProfileDetailDto = approvalProfileService.getApprovalProfile(approvalProfile.getSecuredUuid(), null);

        Assertions.assertEquals(approvalProfile.getName(), approvalProfileDetailDto.getName());
        Assertions.assertEquals(approvalProfile.getTheLatestApprovalProfileVersion().getDescription(), approvalProfileDetailDto.getDescription());
        Assertions.assertEquals(approvalProfile.getTheLatestApprovalProfileVersion().getVersion(), approvalProfileDetailDto.getVersion());
        Assertions.assertEquals(approvalProfile.getTheLatestApprovalProfileVersion().getExpiry(), approvalProfileDetailDto.getExpiry());
        Assertions.assertEquals(2, approvalProfileDetailDto.getApprovalSteps().size());
    }

    @Test
    void testAssociations() throws NotFoundException, AlreadyExistException {
        RaProfile raProfile = getRaProfile();
        VaultProfile vaultProfile = getVaultProfile();

        final ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);

        UUID raProfileUuid = raProfile.getUuid();
        SecuredUUID approvalProfileUUID = approvalProfile.getSecuredUuid();

        Assertions.assertThrows(ValidationException.class, () -> approvalProfileService.associateApprovalProfile(approvalProfileUUID, Resource.CERTIFICATE, raProfileUuid));
        SecuredUUID randomUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        Assertions.assertThrows(NotFoundException.class, () -> approvalProfileService.associateApprovalProfile(randomUuid, Resource.RA_PROFILE, raProfileUuid));
        Assertions.assertThrows(NotFoundException.class, () -> approvalProfileService.associateApprovalProfile(approvalProfileUUID, Resource.RA_PROFILE, randomUuid.getValue()));

        approvalProfileService.associateApprovalProfile(approvalProfileUUID, Resource.RA_PROFILE, raProfileUuid);
        approvalProfileService.associateApprovalProfile(approvalProfileUUID, Resource.VAULT_PROFILE, vaultProfile.getUuid());
        Assertions.assertThrows(AlreadyExistException.class, () -> approvalProfileService.associateApprovalProfile(approvalProfileUUID, Resource.VAULT_PROFILE, vaultProfile.getUuid()));

        List<ResourceObjectDto> resourceObjects = approvalProfileService.getAssociations(approvalProfileUUID);
        Assertions.assertEquals(2, resourceObjects.size());
        Assertions.assertEquals(raProfileUuid, resourceObjects.stream().filter(ro -> ro.getResource().equals(Resource.RA_PROFILE)).findFirst().get().getObjectUuid());
        Assertions.assertEquals(vaultProfile.getUuid(), resourceObjects.stream().filter(ro -> ro.getResource().equals(Resource.VAULT_PROFILE)).findFirst().get().getObjectUuid());

        List<ApprovalProfileDto> approvalProfileDetailDto = approvalProfileService.getAssociatedApprovalProfiles(Resource.RA_PROFILE, raProfileUuid);
        Assertions.assertEquals(1, approvalProfileDetailDto.size());
        Assertions.assertEquals(approvalProfile.getUuid().toString(), approvalProfileDetailDto.getFirst().getUuid());

        approvalProfileDetailDto = approvalProfileService.getAssociatedApprovalProfiles(Resource.VAULT_PROFILE, vaultProfile.getUuid());
        Assertions.assertEquals(1, approvalProfileDetailDto.size());
        Assertions.assertEquals(approvalProfile.getUuid().toString(), approvalProfileDetailDto.getFirst().getUuid());


        Assertions.assertThrows(ValidationException.class, () -> approvalProfileService.disassociateApprovalProfile(approvalProfileUUID, Resource.CERTIFICATE, raProfileUuid));
        Assertions.assertThrows(NotFoundException.class, () -> approvalProfileService.disassociateApprovalProfile(randomUuid, Resource.RA_PROFILE, raProfileUuid));

        approvalProfileService.disassociateApprovalProfile(approvalProfileUUID, Resource.RA_PROFILE, raProfileUuid);
        approvalProfileService.disassociateApprovalProfile(approvalProfileUUID, Resource.VAULT_PROFILE, vaultProfile.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> approvalProfileService.disassociateApprovalProfile(approvalProfileUUID, Resource.RA_PROFILE, raProfileUuid));

        resourceObjects = approvalProfileService.getAssociations(approvalProfileUUID);
        Assertions.assertEquals(0, resourceObjects.size());

        approvalProfileDetailDto = approvalProfileService.getAssociatedApprovalProfiles(Resource.RA_PROFILE, raProfileUuid);
        Assertions.assertEquals(0, approvalProfileDetailDto.size());

        approvalProfileDetailDto = approvalProfileService.getAssociatedApprovalProfiles(Resource.VAULT_PROFILE, vaultProfile.getUuid());
        Assertions.assertEquals(0, approvalProfileDetailDto.size());

    }

    private RaProfile getRaProfile() {
        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReferenceRepository.save(authorityInstanceReference);
        RaProfile raProfile = new RaProfile();
        raProfile.setName("RA Profile");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfileRepository.save(raProfile);
        return raProfile;
    }

    private VaultProfile getVaultProfile() {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("Vault Instance");
        vaultInstanceRepository.save(vaultInstance);
        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("Vault Profile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfileRepository.save(vaultProfile);
        return vaultProfile;
    }

}
