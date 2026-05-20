package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.approval.ApprovalDetailDto;
import com.czertainly.api.model.client.approval.ApprovalResponseDto;
import com.czertainly.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.api.model.client.approvalprofile.ApprovalProfileDetailDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalStepDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserProfileDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.dao.entity.Approval;
import com.czertainly.core.dao.entity.ApprovalProfile;
import com.czertainly.core.dao.repository.ApprovalRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.AuthHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

class ApprovalServiceTest extends ApprovalProfileData {

    private ApprovalService approvalService;

    private ApprovalProfileService approvalProfileService;

    private ApprovalRepository approvalRepository;

    private Approval approval;
    private ApprovalProfile approvalProfile;

    @BeforeEach
    void setUp() throws NotFoundException, AlreadyExistException {
        approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        approval = approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
    }

    @Test
    void testListOfApprovals() throws NotFoundException {
        UUID randomUserUuid = UUID.randomUUID();
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), randomUserUuid, null);
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), randomUserUuid, null);
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), randomUserUuid, null);

        ApprovalResponseDto responseDto = approvalService.listApprovals(SecurityFilter.create(), new PaginationRequestDto());
        Assertions.assertEquals(4, responseDto.getApprovals().size());
    }

    @Test
    void testListUserApprovals() throws NotFoundException, AlreadyExistException {
        final UserProfileDto userProfileDto = AuthHelper.getUserProfile();
        ApprovalProfileRequestDto approvalProfileUpdateRequestDto = new ApprovalProfileRequestDto();
        ApprovalStepDto approvalStepDto = new ApprovalStepDto();
        approvalStepDto.setOrder(1);
        approvalStepDto.setUserUuid(UUID.fromString(userProfileDto.getUser().getUuid()));
        approvalStepDto.setRequiredApprovals(1);
        approvalProfileUpdateRequestDto.getApprovalSteps().add(approvalStepDto);
        ApprovalProfile approvalProfile1 = approvalProfileService.createApprovalProfile(approvalProfileUpdateRequestDto);

        approvalService.createApproval(approvalProfile1.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.fromString(userProfileDto.getUser().getUuid()), null);
        ApprovalResponseDto responseDto = approvalService.listUserApprovals(SecurityFilter.create(), true, new PaginationRequestDto());
        Assertions.assertEquals(1, responseDto.getApprovals().size());

    }

    @Test
    void testDetailOfApproval() throws NotFoundException {
        final ApprovalDetailDto approvalDetailDto = approvalService.getApprovalDetail(approval.getUuid().toString());

        Assertions.assertEquals(approvalProfileRequestDto.getExpiry(), approvalDetailDto.getExpiry());
        Assertions.assertEquals(approvalProfileRequestDto.getDescription(), approvalDetailDto.getDescription());
    }

    @Test
    void testApprovalProfileHistoryVersion() throws NotFoundException {
        approvalService.getApprovalDetail(approval.getUuid().toString());
        approvalProfileService.editApprovalProfile(approvalProfile.getSecuredUuid(), approvalProfileUpdateRequestDto);
        approvalProfileService.editApprovalProfile(approvalProfile.getSecuredUuid(), approvalProfileUpdateRequestDto);

        ApprovalProfileDetailDto approvalProfileDetailDto = approvalProfileService.getApprovalProfile(approvalProfile.getSecuredUuid(), 1);
        Assertions.assertEquals(approvalProfileRequestDto.getDescription(), approvalProfileDetailDto.getDescription());
        approvalProfileDetailDto = approvalProfileService.getApprovalProfile(approvalProfile.getSecuredUuid(), null);
        Assertions.assertEquals(approvalProfileUpdateRequestDto.getDescription(), approvalProfileDetailDto.getDescription());
    }

    @Test
    void testApproveApproval() throws NotFoundException {
        approvalService.approveApproval(approval.getUuid().toString());
        Optional<Approval> approvalOptional = approvalRepository.findByUuid(SecuredUUID.fromUUID(approval.getUuid()));

        Assertions.assertTrue(approvalOptional.isPresent());
        Assertions.assertEquals(ApprovalStatusEnum.APPROVED, approvalOptional.get().getStatus());
    }

    @Test
    void testRejectApproval() throws NotFoundException {
        approvalService.rejectApproval(approval.getUuid().toString());
        Optional<Approval> approvalOptional = approvalRepository.findByUuid(SecuredUUID.fromUUID(approval.getUuid()));

        Assertions.assertTrue(approvalOptional.isPresent());
        Assertions.assertEquals(ApprovalStatusEnum.REJECTED, approvalOptional.get().getStatus());
    }

    @Test
    void testGetResourceObjectInternal() throws NotFoundException {
        NameAndUuidDto result = approvalService.getResourceObjectInternal(approval.getUuid());
        Assertions.assertEquals(approval.getUuid().toString(), result.getUuid());
    }

    @Test
    void testGetResourceObjectInternalNotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> approvalService.getResourceObjectInternal(UUID.randomUUID())
        );
    }

    @Test
    void testGetResourceObjectExternal() throws NotFoundException {
        NameAndUuidDto result = approvalService.getResourceObjectExternal(SecuredUUID.fromUUID(approval.getUuid()));
        Assertions.assertEquals(approval.getUuid().toString(), result.getUuid());
    }

    @Test
    void testGetResourceObjectExternalNotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> approvalService.getResourceObjectExternal(SecuredUUID.fromUUID(UUID.randomUUID()))
        );
    }

    @Test
    void testListResourceObjects() throws NotFoundException {
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);

        List<NameAndUuidDto> result = approvalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(3, result.size());
    }

    @Test
    void testListResourceObjectsWithPagination() throws NotFoundException {
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
        approvalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);

        PaginationRequestDto pagination = new PaginationRequestDto();
        pagination.setPageNumber(1);
        pagination.setItemsPerPage(2);
        List<NameAndUuidDto> result = approvalService.listResourceObjects(SecurityFilter.create(), null, pagination);
        Assertions.assertEquals(2, result.size());
    }

    @Test
    void testEvaluatePermissionChain() {
        Assertions.assertDoesNotThrow(
                () -> approvalService.evaluatePermissionChain(SecuredUUID.fromUUID(approval.getUuid()))
        );
    }

    // SETTERs

    @Autowired
    void setApprovalRepository(ApprovalRepository approvalRepository) {
        this.approvalRepository = approvalRepository;
    }

    @Autowired
    void setApprovalService(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    @Autowired
    void setApprovalProfileService(ApprovalProfileService approvalProfileService) {
        this.approvalProfileService = approvalProfileService;
    }
}
