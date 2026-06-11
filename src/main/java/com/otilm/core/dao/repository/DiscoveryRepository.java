package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.DiscoveryHistory;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DiscoveryRepository extends SecurityFilterRepository<DiscoveryHistory, UUID> {

    Optional<DiscoveryHistory> findByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"triggers"})
    DiscoveryHistory findWithTriggersByUuid(UUID uuid);

	Optional<DiscoveryHistory> findByName(String name);

    @Query("SELECT DISTINCT connectorName FROM DiscoveryHistory ")
    List<String> findDistinctConnectorName();
}
