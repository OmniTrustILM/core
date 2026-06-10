package com.czertainly.core.dao.repository;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.Approval;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.UUID;

@Repository
public interface ApprovalRepository extends SecurityFilterRepository<Approval, UUID> {

    Approval findByResourceAndObjectUuidAndStatus(Resource resource, UUID objectUuid, ApprovalStatusEnum status);

    List<Approval> findByStatusAndExpiryAtLessThan(ApprovalStatusEnum status, Date expiryAt);
}
