package com.czertainly.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.GroupAssociation;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface GroupAssociationRepository extends JpaRepository<GroupAssociation, UUID> {
    List<GroupAssociation> findByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    @EntityGraph(attributePaths = "group")
    List<GroupAssociation> findWithAssociationsByResourceAndObjectUuidIn(Resource resource, List<UUID> objectUuids);

    boolean existsByResourceAndObjectUuidAndGroupUuid(Resource resource, UUID objectUuid, UUID groupUuid);

    Long deleteByGroupUuid(UUID groupUuid);

    Long deleteByResourceAndObjectUuid(Resource resource, UUID objectUuid);
    Long deleteByResourceAndObjectUuidIn(Resource resource, List<UUID> objectUuids);

    Long deleteByResourceAndObjectUuidAndGroupUuid(Resource resource, UUID objectUuid, UUID groupUuid);

}
