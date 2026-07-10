package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approval.ApprovalDetailDto;
import com.otilm.api.model.client.approval.ApprovalResponseDto;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDetailDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SelfPrincipalEndpoint;
import com.otilm.core.service.ApprovalExternalService;
import com.otilm.core.service.ApprovalInternalService;
import com.otilm.core.service.ApprovalProfileData;
import com.otilm.core.service.ApprovalProfileExternalService;
import com.otilm.core.service.impl.ApprovalServiceImpl;
import com.otilm.core.util.AuthHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

class ApprovalServiceITest extends ApprovalProfileData {

    private ApprovalExternalService approvalService;

    private ApprovalInternalService approvalInternalService;

    private ApprovalProfileExternalService approvalProfileService;

    private ApprovalRepository approvalRepository;

    private Approval approval;
    private ApprovalProfile approvalProfile;

    @BeforeEach
    void setUp() throws NotFoundException, AlreadyExistException {
        approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);
        approval = approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
    }

    @Test
    void testListOfApprovals() throws NotFoundException {
        UUID randomUserUuid = UUID.randomUUID();
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), randomUserUuid, null);
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), randomUserUuid, null);
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), randomUserUuid, null);

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

        approvalInternalService.createApproval(approvalProfile1.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.fromString(userProfileDto.getUser().getUuid()), null);
        ApprovalResponseDto responseDto = approvalService.listUserApprovals(true, new PaginationRequestDto());
        Assertions.assertEquals(1, responseDto.getApprovals().size());

    }

    @Test
    void testListUserApprovalsReturnsOnlyOwnApprovals() throws NotFoundException, AlreadyExistException {
        final UserProfileDto userProfileDto = AuthHelper.getUserProfile();

        ApprovalProfileRequestDto ownProfileRequest = new ApprovalProfileRequestDto();
        ownProfileRequest.setName("own-approval-profile");
        ApprovalStepDto ownStep = new ApprovalStepDto();
        ownStep.setOrder(1);
        ownStep.setUserUuid(UUID.fromString(userProfileDto.getUser().getUuid()));
        ownStep.setRequiredApprovals(1);
        ownProfileRequest.getApprovalSteps().add(ownStep);
        ApprovalProfile ownProfile = approvalProfileService.createApprovalProfile(ownProfileRequest);

        ApprovalProfileRequestDto otherProfileRequest = new ApprovalProfileRequestDto();
        otherProfileRequest.setName("other-approval-profile");
        ApprovalStepDto otherStep = new ApprovalStepDto();
        otherStep.setOrder(1);
        otherStep.setUserUuid(UUID.randomUUID());
        otherStep.setRequiredApprovals(1);
        otherProfileRequest.getApprovalSteps().add(otherStep);
        ApprovalProfile otherProfile = approvalProfileService.createApprovalProfile(otherProfileRequest);

        Approval ownApproval = approvalInternalService.createApproval(ownProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.fromString(userProfileDto.getUser().getUuid()), null);
        approvalInternalService.createApproval(otherProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);

        ApprovalResponseDto responseDto = approvalService.listUserApprovals(true, new PaginationRequestDto());

        Assertions.assertEquals(1, responseDto.getApprovals().size(),
                "listUserApprovals must not leak approvals whose steps target another principal");
        Assertions.assertEquals(ownApproval.getUuid().toString(), responseDto.getApprovals().getFirst().getApprovalUuid());
    }

    @Test
    void testListUserApprovalsIsSelfPrincipalEndpoint() throws NoSuchMethodException {
        Method method = ApprovalServiceImpl.class.getMethod("listUserApprovals", boolean.class, PaginationRequestDto.class);

        Assertions.assertTrue(method.isAnnotationPresent(SelfPrincipalEndpoint.class),
                "listUserApprovals must stay a @SelfPrincipalEndpoint so users can list their own approvals without an APPROVAL/LIST grant");
        Assertions.assertFalse(method.isAnnotationPresent(ExternalAuthorization.class),
                "listUserApprovals must not be gated by @ExternalAuthorization again");
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
        NameAndUuidDto result = approvalInternalService.getResourceObjectInternal(approval.getUuid());
        Assertions.assertEquals(approval.getUuid().toString(), result.getUuid());
        Assertions.assertEquals(ResourceAction.CREATE.name() + "/" + Resource.CERTIFICATE.name() + "/" + approval.getObjectUuid(), result.getName());
    }

    @Test
    void testGetResourceObjectInternalNotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> approvalInternalService.getResourceObjectInternal(UUID.randomUUID())
        );
    }

    @Test
    void testGetResourceObjectExternal() throws NotFoundException {
        NameAndUuidDto result = approvalInternalService.getResourceObjectExternal(SecuredUUID.fromUUID(approval.getUuid()));
        Assertions.assertEquals(approval.getUuid().toString(), result.getUuid());
        Assertions.assertEquals(ResourceAction.CREATE.name() + "/" + Resource.CERTIFICATE.name() + "/" + approval.getObjectUuid(), result.getName());
    }

    @Test
    void testGetResourceObjectExternalNotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> approvalInternalService.getResourceObjectExternal(SecuredUUID.fromUUID(UUID.randomUUID()))
        );
    }

    @Test
    void testListResourceObjects() throws NotFoundException {
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);

        List<NameAndUuidDto> result = approvalInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(3, result.size());
        String expectedPrefix = ResourceAction.CREATE.name() + "/" + Resource.CERTIFICATE.name() + "/";
        result.forEach(dto -> Assertions.assertTrue(dto.getName().startsWith(expectedPrefix)));
    }

    @Test
    void testListResourceObjectsWithPagination() throws NotFoundException {
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);
        approvalInternalService.createApproval(approvalProfile.getTheLatestApprovalProfileVersion(), Resource.CERTIFICATE, ResourceAction.CREATE, UUID.randomUUID(), UUID.randomUUID(), null);

        PaginationRequestDto pagination = new PaginationRequestDto();
        pagination.setPageNumber(1);
        pagination.setItemsPerPage(2);
        List<NameAndUuidDto> result = approvalInternalService.listResourceObjects(SecurityFilter.create(), null, pagination);
        Assertions.assertEquals(2, result.size());
        String expectedPrefix = ResourceAction.CREATE.name() + "/" + Resource.CERTIFICATE.name() + "/";
        result.forEach(dto -> Assertions.assertTrue(dto.getName().startsWith(expectedPrefix)));
    }

    @Test
    void testEvaluatePermissionChain() {
        Assertions.assertDoesNotThrow(
                () -> approvalInternalService.evaluatePermissionChain(SecuredUUID.fromUUID(approval.getUuid()))
        );
    }

    // SETTERs

    @Autowired
    void setApprovalRepository(ApprovalRepository approvalRepository) {
        this.approvalRepository = approvalRepository;
    }

    @Autowired
    void setApprovalService(ApprovalExternalService approvalService) {
        this.approvalService = approvalService;
    }

    @Autowired
    void setApprovalInternalService(ApprovalInternalService approvalInternalService) {
        this.approvalInternalService = approvalInternalService;
    }

    @Autowired
    void setApprovalProfileService(ApprovalProfileExternalService approvalProfileService) {
        this.approvalProfileService = approvalProfileService;
    }
}
