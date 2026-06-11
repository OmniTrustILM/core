package com.otilm.core.service;

import com.otilm.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileUpdateRequestDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepDto;
import com.otilm.core.util.BaseSpringBootTest;

import java.util.UUID;

public abstract class ApprovalProfileData extends BaseSpringBootTest {

    protected static final ApprovalProfileRequestDto approvalProfileRequestDto = new ApprovalProfileRequestDto();

    protected static final ApprovalProfileUpdateRequestDto approvalProfileUpdateRequestDto = new ApprovalProfileUpdateRequestDto();

    static {
        prepareApprovalProfile();
        prepareApprovalProfileUpdate();
    }

    protected static void prepareApprovalProfile() {
        final ApprovalStepDto approvalStepDto = new ApprovalStepDto();
        approvalStepDto.setOrder(2);
        approvalStepDto.setUserUuid(UUID.randomUUID());
        approvalStepDto.setDescription("approval-step-1");
        approvalStepDto.setRequiredApprovals(2);

        final ApprovalStepDto approvalStepDto2 = new ApprovalStepDto();
        approvalStepDto2.setOrder(5);
        approvalStepDto2.setRoleUuid(UUID.randomUUID());
        approvalStepDto2.setDescription("approval-step-2");
        approvalStepDto2.setRequiredApprovals(3);

        approvalProfileRequestDto.setName("test-approvalProfile");
        approvalProfileRequestDto.setDescription("test_description");
        approvalProfileRequestDto.setEnabled(true);
        approvalProfileRequestDto.setExpiry(10);
        approvalProfileRequestDto.getApprovalSteps().add(approvalStepDto);
        approvalProfileRequestDto.getApprovalSteps().add(approvalStepDto2);
    }

    protected static void prepareApprovalProfileUpdate() {

        final ApprovalStepDto approvalStepDto = new ApprovalStepDto();
        approvalStepDto.setOrder(2);
        approvalStepDto.setUserUuid(UUID.randomUUID());
        approvalStepDto.setDescription("approval-step-1");
        approvalStepDto.setRequiredApprovals(2);

        final ApprovalStepDto approvalStepDto2 = new ApprovalStepDto();
        approvalStepDto2.setOrder(5);
        approvalStepDto2.setRoleUuid(UUID.randomUUID());
        approvalStepDto2.setDescription("approval-step-2");
        approvalStepDto2.setRequiredApprovals(3);

        final ApprovalStepDto approvalStepDto3 = new ApprovalStepDto();
        approvalStepDto3.setOrder(10);
        approvalStepDto3.setRoleUuid(UUID.randomUUID());
        approvalStepDto3.setDescription("approval-step-extra");
        approvalStepDto3.setRequiredApprovals(10);

        approvalProfileUpdateRequestDto.setExpiry(20);
        approvalProfileUpdateRequestDto.setDescription("test_description_updated");
        approvalProfileUpdateRequestDto.getApprovalSteps().add(approvalStepDto);
        approvalProfileUpdateRequestDto.getApprovalSteps().add(approvalStepDto2);
        approvalProfileUpdateRequestDto.getApprovalSteps().add(approvalStepDto3);
    }

}
