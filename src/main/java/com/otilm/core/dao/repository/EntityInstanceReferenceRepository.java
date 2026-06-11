package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.EntityInstanceReference;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EntityInstanceReferenceRepository extends SecurityFilterRepository<EntityInstanceReference, Long> {

    Optional<EntityInstanceReference> findByUuid(UUID uuid);

    Optional<EntityInstanceReference> findByName(String name);

    @Query("SELECT DISTINCT connectorName FROM EntityInstanceReference")
    List<String> findDistinctConnectorName();

    @Query("SELECT DISTINCT kind FROM EntityInstanceReference")
    List<String> findDistinctKind();
}
