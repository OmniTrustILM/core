package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.approvalprofile.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceObjectDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.dao.entity.ApprovalProfile;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface ApprovalProfileExternalService {

    ApprovalProfileResponseDto listApprovalProfiles(final SecurityFilter securityFilter, final PaginationRequestDto paginationRequestDto);

    ApprovalProfileDetailDto getApprovalProfile(SecuredUUID uuid, Integer version) throws NotFoundException;

    void deleteApprovalProfile(SecuredUUID uuid) throws NotFoundException, ValidationException;

    ApprovalProfile createApprovalProfile(ApprovalProfileRequestDto approvalProfileRequestDto) throws NotFoundException, AlreadyExistException;

    ApprovalProfile editApprovalProfile(SecuredUUID uuid, ApprovalProfileUpdateRequestDto approvalProfileUpdateRequestDto) throws NotFoundException;

    List<ResourceObjectDto> getAssociations(SecuredUUID approvalProfileUuid) throws NotFoundException;

    void associateApprovalProfile(SecuredUUID approvalProfileUUID, Resource resource, UUID associationObjectUuid) throws NotFoundException, AlreadyExistException;

    void disassociateApprovalProfile(SecuredUUID approvalProfileUuid, Resource resource, UUID associationObjectUuid) throws NotFoundException;

    List<ApprovalProfileDto> getAssociatedApprovalProfiles(Resource resource, UUID associationObjectUuid);
}
