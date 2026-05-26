package com.czertainly.core.api.web;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.ApprovalController;
import com.czertainly.api.model.client.approval.ApprovalDetailDto;
import com.czertainly.api.model.client.approval.ApprovalResponseDto;
import com.czertainly.api.model.client.approval.ApprovalUserDto;
import com.czertainly.api.model.client.approval.UserApprovalDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ApprovalExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApprovalControllerImpl implements ApprovalController {

    private ApprovalExternalService approvalService;

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.LIST)
    public ApprovalResponseDto listApprovals(PaginationRequestDto paginationRequestDto) {
        return approvalService.listApprovals(SecurityFilter.create(), paginationRequestDto);
    }

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.LIST)
    public ApprovalResponseDto listUserApprovals(PaginationRequestDto paginationRequestDto, ApprovalUserDto approvalUserDto) {
        return approvalService.listUserApprovals(SecurityFilter.create(), approvalUserDto.isHistory(), paginationRequestDto);
    }

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.DETAIL)
    public ApprovalDetailDto getApproval(@LogResource(uuid = true) final String uuid) throws NotFoundException {
        return approvalService.getApprovalDetail(uuid);
    }

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.APPROVE_OVERRIDE)
    public void approveApproval(@LogResource(uuid = true) final String uuid) throws NotFoundException {
        approvalService.approveApproval(uuid);
    }

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.REJECT_OVERRIDE)
    public void rejectApproval(@LogResource(uuid = true) final String uuid) throws NotFoundException {
        approvalService.rejectApproval(uuid);
    }

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.APPROVE)
    public void approveApprovalRecipient(@LogResource(uuid = true) final String uuid, final UserApprovalDto userApprovalDto) throws NotFoundException {
        approvalService.approveApprovalRecipient(uuid, userApprovalDto);
    }

    @Override
    @AuditLogged(module = Module.APPROVALS, resource = Resource.APPROVAL, operation = Operation.REJECT)
    public void rejectApprovalRecipient(@LogResource(uuid = true) final String uuid, final UserApprovalDto userApprovalDto) throws NotFoundException {
        approvalService.rejectApprovalRecipient(uuid, userApprovalDto);
    }

    // SETTERs

    @Autowired
    public void setApprovalService(ApprovalExternalService approvalService) {
        this.approvalService = approvalService;
    }
}
