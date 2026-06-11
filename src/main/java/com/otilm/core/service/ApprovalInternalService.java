package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfileVersion;
import com.otilm.core.model.auth.ResourceAction;

import java.util.UUID;

public interface ApprovalInternalService extends ResourceExtensionService {

    Approval createApproval(final ApprovalProfileVersion approvalProfileVersion, final Resource resource, final ResourceAction resourceAction, final UUID objectUuid, final UUID userUuid, final Object objectData) throws NotFoundException;

    int checkApprovalsExpiration();
}
