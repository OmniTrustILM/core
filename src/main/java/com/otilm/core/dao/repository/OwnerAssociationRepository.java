package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.OwnerAssociation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface OwnerAssociationRepository extends JpaRepository<OwnerAssociation, UUID> {
    // owner associations
    OwnerAssociation findByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    Long deleteByOwnerUuid(UUID ownerUuid);

    Long deleteByResourceAndObjectUuidAndOwnerUuidNotNull(Resource resource, UUID objectUuid);
    Long deleteByResourceAndObjectUuidInAndOwnerUuidNotNull(Resource resource, List<UUID> objectUuids);

    Long countByOwnerUuidAndResourceAndObjectUuidIn(UUID ownerUuid, Resource resource, List<UUID> objectUuids);
}
