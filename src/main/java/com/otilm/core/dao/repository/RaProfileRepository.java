package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RaProfileRepository extends SecurityFilterRepository<RaProfile, Long> {

    Optional<RaProfile> findByUuid(UUID uuid);

    /**
     * Loads an RA profile with its authority, connector and connector interface eagerly.
     */
    @EntityGraph(attributePaths = {
            "authorityInstanceReference",
            "authorityInstanceReference.connectorInterface",
            "authorityInstanceReference.connector"
    })
    Optional<RaProfile> findWithAuthorityByUuid(UUID uuid);

    Optional<RaProfile> findByName(String name);

    Optional<RaProfile> findByNameAndEnabledIsTrue(String name);

    Optional<RaProfile> findByUuidAndEnabledIsTrue(UUID uuid);

    List<RaProfile> findAllByAcmeProfileUuid(UUID acmeProfileUuid);

    List<RaProfile> findAllByScepProfileUuid(UUID scepProfileUuid);

    List<RaProfile> findAllByCmpProfileUuid(UUID cmpProfileUuid);

    List<RaProfile> findAllByUuidIn(List<UUID>uuids);
}
