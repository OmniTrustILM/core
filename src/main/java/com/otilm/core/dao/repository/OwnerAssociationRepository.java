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

    /**
     * Returns those of {@code resources} with at least one object owned by {@code ownerUuid}, or assigned to one of
     * {@code groupUuids} (to any group when {@code allGroups}). Both lists are Postgres array literals, so an empty
     * group list matches nothing rather than rendering an invalid {@code IN ()}.
     */
    @Query(value = """
            SELECT r.resource FROM unnest(CAST(:resources AS text[])) AS r(resource)
            WHERE EXISTS (SELECT 1 FROM owner_association oa
                          WHERE oa.owner_uuid = :ownerUuid AND oa.resource = r.resource)
               OR EXISTS (SELECT 1 FROM group_association ga
                          WHERE ga.resource = r.resource
                            AND (:allGroups OR ga.group_uuid = ANY (CAST(:groupUuids AS uuid[]))))
            """, nativeQuery = true)
    List<String> findResourcesWithOwnedOrGroupAssignedObjects(@Param("resources") String resources,
            @Param("ownerUuid") UUID ownerUuid, @Param("allGroups") boolean allGroups,
            @Param("groupUuids") String groupUuids);
}
