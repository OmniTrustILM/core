package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approval.ApprovalDetailDto;
import com.otilm.api.model.client.approval.ApprovalResponseDto;
import com.otilm.api.model.client.approval.UserApprovalDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.UUID;

public interface ApprovalExternalService {

    ApprovalResponseDto listApprovals(final SecurityFilter securityFilter, final PaginationRequestDto paginationRequestDto);

    ApprovalResponseDto listApprovalsByObject(final SecurityFilter securityFilter, final Resource resource, final UUID objectUuid, final PaginationRequestDto paginationRequestDto);

    ApprovalResponseDto listUserApprovals(final boolean withHistory, final PaginationRequestDto paginationRequestDto);

    ApprovalDetailDto getApprovalDetail(final String uuid) throws NotFoundException;

    void approveApproval(final String uuid) throws NotFoundException;

    void rejectApproval(final String uuid) throws NotFoundException;

    void approveApprovalRecipient(final String uuid, final UserApprovalDto userApprovalDto) throws NotFoundException;

    void rejectApprovalRecipient(final String uuid, final UserApprovalDto userApprovalDto) throws NotFoundException;
}
