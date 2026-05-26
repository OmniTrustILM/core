package com.czertainly.core.dao.repository.workflows;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.workflows.Rule;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RuleRepository extends SecurityFilterRepository<Rule, UUID> {

    boolean existsByName(String name);

    boolean existsByNameAndUuidNot(String name, UUID uuid);

    @EntityGraph(attributePaths = {"triggers"})
    Optional<Rule> findWithTriggersByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"conditions", "conditions.items"})
    Optional<Rule> findWithConditionsByUuid(UUID uuid);

    @Query("SELECT r FROM Rule r WHERE r.resource = ?1 OR r.resource = ?#{T(com.czertainly.api.model.core.auth.Resource).ANY}")
    List<Rule> findAllByResource(Resource resource);


}
