package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.OwnerAssociation;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface OwnerAssociationRepository extends JpaRepository<OwnerAssociation, UUID> {
    // owner associations
    OwnerAssociation findByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    Long deleteByOwnerUuid(UUID ownerUuid);

    Long deleteByResourceAndObjectUuidAndOwnerUuidNotNull(Resource resource, UUID objectUuid);

    Long deleteByResourceAndObjectUuidInAndOwnerUuidNotNull(Resource resource, List<UUID> objectUuids);

    @Query("SELECT COUNT(DISTINCT oa.objectUuid) FROM OwnerAssociation oa WHERE oa.ownerUuid = :ownerUuid"
            + " AND oa.resource = :resource AND oa.objectUuid IN :objectUuids")
    long countOwnedObjects(@Param("ownerUuid") UUID ownerUuid, @Param("resource") Resource resource,
            @Param("objectUuids") List<UUID> objectUuids);
}
