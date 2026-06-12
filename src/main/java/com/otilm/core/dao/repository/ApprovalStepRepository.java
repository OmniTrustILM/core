package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ApprovalStep;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ApprovalStepRepository extends SecurityFilterRepository<ApprovalStep, UUID> {

    @Query("SELECT aps " +
            "FROM ApprovalStep aps " +
            "    LEFT JOIN Approval a on aps.approvalProfileVersionUuid = a.approvalProfileVersionUuid " +
            "    LEFT OUTER JOIN ApprovalRecipient ar on aps.uuid = ar.approvalStepUuid and a.uuid = ar.approvalUuid " +
            "where a.uuid = :approvalUuid " +
            "group by aps.uuid, aps.requiredApprovals, aps.order " +
            "having count(ar) < aps.requiredApprovals " +
            "order by aps.order " +
            "limit 1")
    ApprovalStep findNextApprovalStepForApproval(final UUID approvalUuid);


}
