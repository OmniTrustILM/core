package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.approvalprofile.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceObjectDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.ApprovalProfileRelationRepository;
import com.czertainly.core.dao.repository.ApprovalProfileRepository;
import com.czertainly.core.dao.repository.ApprovalProfileVersionRepository;
import com.czertainly.core.dao.repository.ApprovalStepRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ApprovalProfileExternalService;
import com.czertainly.core.service.ResourceInternalService;
import com.czertainly.core.util.ApprovalRecipientHelper;
import com.czertainly.core.util.RequestValidatorHelper;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional

public class ApprovalProfileServiceImpl implements ApprovalProfileExternalService {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalProfileServiceImpl.class);
    public static final String RESOURCE_DOES_NOT_SUPPORT_APPROVAL_PROFILES = "Resource %s does not support approval profiles";

    private ApprovalProfileRepository approvalProfileRepository;

    private ApprovalStepRepository approvalStepRepository;

    private ApprovalProfileVersionRepository approvalProfileVersionRepository;

    private ApprovalRecipientHelper approvalRecipientHelper;

    private ApprovalProfileRelationRepository approvalProfileRelationRepository;

    private ResourceInternalService resourceService;

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.LIST)
    public ApprovalProfileResponseDto listApprovalProfiles(final SecurityFilter filter, final PaginationRequestDto paginationRequestDto) {
        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);
        final Pageable pageable = PageRequest.of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<ApprovalProfile> approvalProfileList = approvalProfileRepository.findUsingSecurityFilter(filter, List.of("approvalProfileRelations"), null, pageable, null);

        final Long maxItems = approvalProfileRepository.countUsingSecurityFilter(filter, null);
        final ApprovalProfileResponseDto responseDto = new ApprovalProfileResponseDto();
        responseDto.setApprovalProfiles(approvalProfileList.stream().map(approvalProfile -> approvalProfile.getTheLatestApprovalProfileVersion().mapToDto()).toList());
        responseDto.setItemsPerPage(paginationRequestDto.getItemsPerPage());
        responseDto.setPageNumber(paginationRequestDto.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / paginationRequestDto.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.DETAIL)
    public ApprovalProfileDetailDto getApprovalProfile(final SecuredUUID uuid, final Integer version) throws NotFoundException {
        ApprovalProfileDetailDto approvalProfileDetailDto;
        if (version == null) {
            approvalProfileDetailDto = findApprovalProfileByUuid(uuid).getTheLatestApprovalProfileVersion().mapToDtoWithSteps();
        } else {
            approvalProfileDetailDto = findApprovalProfileByUuid(uuid).getApprovalProfileVersionByVersion(version).mapToDtoWithSteps();
        }

        approvalProfileDetailDto.getApprovalSteps().forEach(approvalStep -> approvalRecipientHelper.fillApprovalStepDto(approvalStep));
        return approvalProfileDetailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.DELETE)
    public void deleteApprovalProfile(final SecuredUUID uuid) throws NotFoundException, ValidationException {
        final ApprovalProfile approvalProfile = findApprovalProfileByUuid(uuid);
        if (approvalProfile.getApprovalProfileVersions().stream().anyMatch(apv -> (apv.getApprovals() != null && !apv.getApprovals().isEmpty()))) {
            throw new ValidationException(ValidationError.create("Unable to delete approval profile with existing approvals."));
        }
        approvalProfile.getApprovalProfileVersions().forEach(apv -> {
            approvalStepRepository.deleteAll(apv.getApprovalSteps());
            approvalProfileVersionRepository.delete(apv);
        });
        approvalProfileRepository.delete(approvalProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.CREATE)
    public ApprovalProfile createApprovalProfile(final ApprovalProfileRequestDto approvalProfileRequestDto) throws NotFoundException, AlreadyExistException {
        if (approvalProfileRequestDto.getExpiry() != null && approvalProfileRequestDto.getExpiry() <= 0) {
            throw new ValidationException("Expiry value (if set) should be greater than 0");
        }
        if (approvalProfileRepository.findByName(approvalProfileRequestDto.getName()).isPresent()) {
            throw new AlreadyExistException("Approval profile with name " + approvalProfileRequestDto.getName() + " already exists.");
        }

        final ApprovalProfile approvalProfile = new ApprovalProfile();
        approvalProfile.setName(approvalProfileRequestDto.getName());
        approvalProfileRepository.save(approvalProfile);

        final ApprovalProfileVersion approvalProfileVersion = new ApprovalProfileVersion();
        approvalProfileVersion.setExpiry(approvalProfileRequestDto.getExpiry());
        approvalProfileVersion.setDescription(approvalProfileRequestDto.getDescription());
        approvalProfileVersion.setApprovalProfileUuid(approvalProfile.getUuid());
        approvalProfileVersion.setApprovalProfile(approvalProfile);
        approvalProfileVersionRepository.save(approvalProfileVersion);

        approvalProfile.getApprovalProfileVersions().add(approvalProfileVersion);

        createApprovalSteps(approvalProfileVersion, approvalProfileRequestDto.getApprovalSteps());
        return approvalProfile;
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.UPDATE)
    public ApprovalProfile editApprovalProfile(final SecuredUUID uuid, final ApprovalProfileUpdateRequestDto approvalProfileUpdateRequestDto) throws NotFoundException {
        if (approvalProfileUpdateRequestDto.getExpiry() != null && approvalProfileUpdateRequestDto.getExpiry() <= 0) {
            throw new ValidationException("Expiry value (if set) should be greater than 0");
        }

        final ApprovalProfile approvalProfile = findApprovalProfileByUuid(uuid);
        ApprovalProfileVersion latestVersion = approvalProfile.getTheLatestApprovalProfileVersion();
        if (approvalProfileVersionsEqual(latestVersion, approvalProfileUpdateRequestDto)) {
            logger.debug("Latest version of approval profile {} is same as in request. New version is not created", approvalProfile.getName());
            return approvalProfile;
        }

        // check existence of approvals, if no approvals associated update current latest version
        boolean createNewVersion = !latestVersion.getApprovals().isEmpty();
        if (createNewVersion) {
            latestVersion = latestVersion.createNewVersionObject();
            logger.debug("Creating new version of approval profile {} version {}.", approvalProfile.getName(), latestVersion.getVersion());
        } else {
            logger.debug("Updating latest version of approval profile {}.", approvalProfile.getName());

            for (ApprovalStep step : latestVersion.getApprovalSteps()) {
                approvalStepRepository.delete(step);
            }
            latestVersion.getApprovalSteps().clear();
        }

        latestVersion.setDescription(approvalProfileUpdateRequestDto.getDescription());
        latestVersion.setExpiry(approvalProfileUpdateRequestDto.getExpiry());

        approvalProfileVersionRepository.save(latestVersion);
        if (createNewVersion) approvalProfile.getApprovalProfileVersions().add(latestVersion);
        createApprovalSteps(latestVersion, approvalProfileUpdateRequestDto.getApprovalSteps());

        return latestVersion.getApprovalProfile();
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.DETAIL)
    public List<ResourceObjectDto> getAssociations(SecuredUUID approvalProfileUuid) throws NotFoundException {
        ApprovalProfile approvalProfile = approvalProfileRepository.findByUuid(approvalProfileUuid).orElseThrow(() -> new NotFoundException(ApprovalProfile.class, approvalProfileUuid));
        List<ResourceObjectDto> resourceObjects = new ArrayList<>();
        for (ApprovalProfileRelation relation : approvalProfile.getApprovalProfileRelations()) {
            resourceObjects.add(resourceService.getResourceObject(relation.getResource(), relation.getResourceUuid()));
        }
        return resourceObjects;
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.UPDATE)
    public void associateApprovalProfile(SecuredUUID approvalProfileUUID, Resource resource, UUID associationObjectUuid) throws NotFoundException, AlreadyExistException {
        if (!resource.hasApprovalProfiles()) {
            throw new ValidationException(RESOURCE_DOES_NOT_SUPPORT_APPROVAL_PROFILES.formatted(resource.getLabel()));
        }

        if (!approvalProfileRepository.existsById(approvalProfileUUID.getValue())) {
            throw new NotFoundException(ApprovalProfile.class, approvalProfileUUID.getValue());
        }

        // Call to check if the associated resource exists, will throw NotFoundException if not found
        resourceService.getResourceObjectInternal(resource, associationObjectUuid);

        if (approvalProfileRelationRepository.existsByResourceAndResourceUuid(resource, associationObjectUuid)) {
            throw new AlreadyExistException("An approval profile is already associated to %s with UUID %s".formatted(resource.getLabel(), associationObjectUuid));
        }
        ApprovalProfileRelation relation = new ApprovalProfileRelation();
        relation.setResource(resource);
        relation.setResourceUuid(associationObjectUuid);
        relation.setApprovalProfileUuid(approvalProfileUUID.getValue());
        approvalProfileRelationRepository.save(relation);
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.UPDATE)
    public void disassociateApprovalProfile(SecuredUUID approvalProfileUuid, Resource resource, UUID associationObjectUuid) throws NotFoundException {
        if (!resource.hasApprovalProfiles()) {
            throw new ValidationException(RESOURCE_DOES_NOT_SUPPORT_APPROVAL_PROFILES.formatted(resource.getLabel()));
        }

        if (!approvalProfileRepository.existsById(approvalProfileUuid.getValue())) {
            throw new NotFoundException(ApprovalProfile.class, approvalProfileUuid);
        }
        if (!approvalProfileRelationRepository.existsByApprovalProfileUuidAndResourceAndResourceUuid(approvalProfileUuid.getValue(), resource, associationObjectUuid)) {
            throw new NotFoundException("Approval profile is not associated to %s with UUID %s".formatted(resource.getLabel(), associationObjectUuid));
        }
        approvalProfileRelationRepository.deleteByApprovalProfileUuidAndResourceAndResourceUuid(approvalProfileUuid.getValue(), resource, associationObjectUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL_PROFILE, action = ResourceAction.LIST)
    public List<ApprovalProfileDto> getAssociatedApprovalProfiles(Resource resource, UUID associationObjectUuid) {
        if (!resource.hasApprovalProfiles()) {
            throw new ValidationException(RESOURCE_DOES_NOT_SUPPORT_APPROVAL_PROFILES.formatted(resource.getLabel()));
        }
        List<ApprovalProfileRelation> relations = approvalProfileRelationRepository.findDistinctByResourceAndResourceUuid(resource, associationObjectUuid);
        return relations.stream().map(r -> r.getApprovalProfile().getTheLatestApprovalProfileVersion().mapToDto()).toList();
    }

    private boolean approvalProfileVersionsEqual(ApprovalProfileVersion latestVersion, ApprovalProfileUpdateRequestDto request) {
        // check approval profile props
        if (latestVersion.getApprovalSteps().size() != request.getApprovalSteps().size() || !Objects.equals(latestVersion.getExpiry(), request.getExpiry()) || !StringUtils.equals(latestVersion.getDescription(), request.getDescription())) {
            return false;
        }

        // check approval profile steps
        List<ApprovalStep> actualSteps = latestVersion.getApprovalSteps();
        actualSteps.sort(Comparator.comparingInt(ApprovalStep::getOrder));
        for (int i = 0; i < actualSteps.size(); i++) {
            if (!Objects.equals(actualSteps.get(i).getUserUuid(), request.getApprovalSteps().get(i).getUserUuid())
                    || !Objects.equals(actualSteps.get(i).getGroupUuid(), request.getApprovalSteps().get(i).getGroupUuid())
                    || !Objects.equals(actualSteps.get(i).getRoleUuid(), request.getApprovalSteps().get(i).getRoleUuid())
                    || !StringUtils.equals(actualSteps.get(i).getDescription(), request.getApprovalSteps().get(i).getDescription())
                    || actualSteps.get(i).getRequiredApprovals() != request.getApprovalSteps().get(i).getRequiredApprovals()) {
                return false;
            }
        }

        return true;
    }

    private void createApprovalSteps(final ApprovalProfileVersion approvalProfileVersion, final List<ApprovalStepRequestDto> approvalStepDtos) throws ValidationException {
        if (approvalStepDtos == null || approvalStepDtos.isEmpty()) {
            throw new ValidationException("Unable to process approval profile without approval steps.");
        }

        approvalStepDtos.forEach(as -> {
            if (as.getRequiredApprovals() <= 0) {
                throw new ValidationException("Required approvals value should be greater than 0");
            }
            validateAssignedPersons(as);

            final ApprovalStep approvalStep = new ApprovalStep();
            approvalStep.setApprovalProfileVersion(approvalProfileVersion);
            approvalStep.setApprovalProfileVersionUuid(approvalProfileVersion.getUuid());
            approvalStep.setOrder(as.getOrder());
            approvalStep.setGroupUuid(as.getGroupUuid());
            approvalStep.setUserUuid(as.getUserUuid());
            approvalStep.setRoleUuid(as.getRoleUuid());
            approvalStep.setDescription(as.getDescription());
            approvalStep.setRequiredApprovals(as.getRequiredApprovals());
            approvalStepRepository.save(approvalStep);
            approvalProfileVersion.getApprovalSteps().add(approvalStep);
        });
        approvalProfileVersionRepository.save(approvalProfileVersion);
    }

    private void validateAssignedPersons(final ApprovalStepRequestDto as) {
        boolean isAssignedResponsibleUser = false;
        if (as.getRoleUuid() != null) {
            isAssignedResponsibleUser = true;
        }
        if (as.getUserUuid() != null) {
            if (isAssignedResponsibleUser) {
                throw new ValidationException(ValidationError.create("There is forbidden to have more than one assigned user/role/group."));
            }
            isAssignedResponsibleUser = true;
        }
        if (as.getGroupUuid() != null) {
            if (isAssignedResponsibleUser) {
                throw new ValidationException(ValidationError.create("There is forbidden to have more than one assigned user/role/group."));
            }
            isAssignedResponsibleUser = true;
        }

        if (!isAssignedResponsibleUser) {
            throw new ValidationException(ValidationError.create("There is required to have assigned one of user/role/group."));
        }
    }

    private ApprovalProfile findApprovalProfileByUuid(final SecuredUUID uuid) throws NotFoundException {
        final Optional<ApprovalProfile> approvalProfileOptional = approvalProfileRepository.findByUuid(uuid);
        if (approvalProfileOptional.isPresent()) {
            return approvalProfileOptional.get();
        }
        throw new NotFoundException("Unable to find approval profile with UUID: {}", uuid);
    }


    // SETTERs

    @Autowired
    public void setApprovalProfileRepository(ApprovalProfileRepository approvalProfileRepository) {
        this.approvalProfileRepository = approvalProfileRepository;
    }

    @Autowired
    public void setApprovalStepRepository(ApprovalStepRepository approvalStepRepository) {
        this.approvalStepRepository = approvalStepRepository;
    }

    @Autowired
    public void setApprovalProfileVersionRepository(ApprovalProfileVersionRepository approvalProfileVersionRepository) {
        this.approvalProfileVersionRepository = approvalProfileVersionRepository;
    }

    @Autowired
    public void setApprovalRecipientHelper(ApprovalRecipientHelper approvalRecipientHelper) {
        this.approvalRecipientHelper = approvalRecipientHelper;
    }

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setApprovalProfileRelationRepository(ApprovalProfileRelationRepository approvalProfileRelationRepository) {
        this.approvalProfileRelationRepository = approvalProfileRelationRepository;
    }
}
