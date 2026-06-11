package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.ComplianceProfileAssociation;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ComplianceProfileAssociationRepository extends SecurityFilterRepository<ComplianceProfileAssociation, UUID> {

    List<ComplianceProfileAssociation> findByComplianceProfileUuidAndResource(UUID complianceProfileUuid, Resource resource);

    @EntityGraph(attributePaths = {"complianceProfile"})
    List<ComplianceProfileAssociation> findDistinctByResourceAndObjectUuid(Resource resource, UUID associationObjectUuid);

    Long countByResourceAndObjectUuid(Resource resource, UUID associationObjectUuid);

    void deleteByComplianceProfileUuid(UUID complianceProfileUuid);

    boolean existsByComplianceProfileUuidAndResourceAndObjectUuid(UUID complianceProfileUuid, Resource resource, UUID associationObjectUuid);

    void deleteByComplianceProfileUuidAndResourceAndObjectUuid(UUID complianceProfileUuid, Resource resource, UUID associationObjectUuid);

}
