package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.Approval;
import com.czertainly.core.dao.entity.ApprovalProfileVersion;
import com.czertainly.core.model.auth.ResourceAction;

import java.util.UUID;

public interface ApprovalInternalService {

    Approval createApproval(final ApprovalProfileVersion approvalProfileVersion, final Resource resource, final ResourceAction resourceAction, final UUID objectUuid, final UUID userUuid, final Object objectData) throws NotFoundException;

    int checkApprovalsExpiration();
}
