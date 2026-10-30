package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.ComplianceProfileAssociation;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ComplianceProfileAssociationRepository
        extends
            SecurityFilterRepository<ComplianceProfileAssociation, UUID> {

    List<ComplianceProfileAssociation> findByComplianceProfileUuidAndResource(UUID complianceProfileUuid,
            Resource resource);

    @EntityGraph(attributePaths = {"complianceProfile"})
    List<ComplianceProfileAssociation> findDistinctByResourceAndObjectUuid(Resource resource,
            UUID associationObjectUuid);

    Long countByResourceAndObjectUuid(Resource resource, UUID associationObjectUuid);

    boolean existsByResourceAndObjectUuidIn(Resource resource, List<UUID> associationObjectUuids);

    boolean existsByComplianceProfileUuidAndResourceAndObjectUuid(UUID complianceProfileUuid, Resource resource,
            UUID associationObjectUuid);

    /**
     * The deletes below are bulk statements: an object delete removes associations concurrently with them, and a row
     * another transaction already removed must not fail the delete.
     */
    @Modifying
    @Query("DELETE FROM ComplianceProfileAssociation a WHERE a.complianceProfileUuid = :complianceProfileUuid")
    int deleteByComplianceProfileUuid(@Param("complianceProfileUuid") UUID complianceProfileUuid);

    @Modifying
    @Query("DELETE FROM ComplianceProfileAssociation a WHERE a.complianceProfileUuid = :complianceProfileUuid"
            + " AND a.resource = :resource AND a.objectUuid = :objectUuid")
    int deleteByComplianceProfileUuidAndResourceAndObjectUuid(
            @Param("complianceProfileUuid") UUID complianceProfileUuid, @Param("resource") Resource resource,
            @Param("objectUuid") UUID objectUuid);

    @Modifying
    @Query("DELETE FROM ComplianceProfileAssociation a WHERE a.resource = :resource AND a.objectUuid = :objectUuid")
    int deleteByResourceAndObjectUuid(@Param("resource") Resource resource, @Param("objectUuid") UUID objectUuid);

    @Modifying
    @Query("DELETE FROM ComplianceProfileAssociation a WHERE a.resource = :resource AND a.objectUuid IN :objectUuids")
    int deleteByResourceAndObjectUuidIn(@Param("resource") Resource resource,
            @Param("objectUuids") Collection<UUID> objectUuids);

}
