package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Location;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface LocationRepository extends SecurityFilterRepository<Location, Long> {

    Optional<Location> findByUuid(UUID uuid);

    Optional<Location> findByName(String name);

    List<Location> findByEntityInstanceReference(EntityInstanceReference entityInstanceReference);

    Optional<Location> findByUuidAndEnabledIsTrue(UUID uuid);

    @Query("SELECT DISTINCT entityInstanceName FROM Location")
    List<String> findDistinctEntityInstanceName();
}
