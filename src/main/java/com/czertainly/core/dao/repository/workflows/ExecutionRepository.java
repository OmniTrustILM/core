package com.czertainly.core.dao.repository.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.workflows.Execution;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ExecutionRepository extends SecurityFilterRepository<Execution, UUID> {

    boolean existsByName(String name);

    boolean existsByNameAndUuidNot(String name, UUID uuid);

    @EntityGraph(attributePaths = {"actions"})
    Optional<Execution> findWithActionsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"items", "items.notificationProfile"})
    Optional<Execution> findWithItemsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"items", "items.notificationProfile"})
    List<Execution> findAllWithItemsBy();

    @EntityGraph(attributePaths = {"items", "items.notificationProfile"})
    @Query("SELECT e FROM Execution e WHERE e.resource = ?1 OR e.resource = ?#{T(com.otilm.api.model.core.auth.Resource).ANY}")
    List<Execution> findAllByResource(Resource resource);

    List<Execution> findByItemsNotificationProfileUuid(UUID uuid);

}
