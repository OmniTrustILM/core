package com.czertainly.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.ApprovalProfileRelation;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ApprovalProfileRelationRepository extends SecurityFilterRepository<ApprovalProfileRelation, UUID> {

    Optional<List<ApprovalProfileRelation>> findByResourceUuid(final UUID resourceUuid);

    @EntityGraph(attributePaths = {"approvalProfile", "approvalProfile.approvalProfileVersions"})
    Optional<List<ApprovalProfileRelation>> findByResourceUuidAndResource(final UUID resourceUuid, final Resource resource);

    boolean existsByApprovalProfileUuidAndResourceAndResourceUuid(UUID approvalProfileUuid, Resource resource, UUID resourceUuid);

    void deleteByApprovalProfileUuidAndResourceAndResourceUuid(UUID value, Resource resource, UUID associationObjectUuid);

    List<ApprovalProfileRelation> findDistinctByResourceAndResourceUuid(Resource resource, UUID associationObjectUuid);

    boolean existsByResourceAndResourceUuid(Resource resource, UUID resourceUuid);

}
