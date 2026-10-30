package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ApprovalProfile;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

@Repository
public interface ApprovalProfileRepository extends SecurityFilterRepository<ApprovalProfile, UUID> {

    Optional<ApprovalProfile> findByName(String name);

    @EntityGraph(attributePaths = {"approvalProfileVersions"})
    Optional<ApprovalProfile> findWithVersionsByUuid(UUID uuid);

}
