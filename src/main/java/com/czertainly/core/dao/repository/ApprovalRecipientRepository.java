package com.czertainly.core.dao.repository;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.core.dao.entity.ApprovalRecipient;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ApprovalRecipientRepository extends SecurityFilterRepository<ApprovalRecipient, UUID> {

    @Query("SELECT ar " +
            "FROM ApprovalRecipient ar JOIN ApprovalStep aps ON aps.uuid = ar.approvalStepUuid " +
            "WHERE ar.status = :status AND ar.approvalUuid = :approvalUuid AND " +
            "      (aps.groupUuid IN :groupUuid" +
            "          OR aps.roleUuid IN :roleUuid" +
            "          OR aps.userUuid = :userUuid)")
    List<ApprovalRecipient> findByResponsiblePersonAndStatusAndApproval(final UUID userUuid, final List<UUID> roleUuid, final List<UUID> groupUuid, final ApprovalStatusEnum status, final UUID approvalUuid);

    List<ApprovalRecipient> findApprovalRecipientsByApprovalUuidAndStatus(final UUID approvalUuid, final ApprovalStatusEnum status);

    List<ApprovalRecipient> findByApprovalUuidAndUserUuid(final UUID approvalUuid, final UUID userUuid);

}
