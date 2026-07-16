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
     * Loads an RA profile with its authority, connector, connector interface and the connector's
     * function groups eagerly. The function groups are fetched so callers that traverse the connector
     * outside an active transaction (e.g. request-attribute resolution under
     * {@code Propagation.NOT_SUPPORTED}) do not depend on open-session-in-view for the lazy collection.
     */
    @EntityGraph(attributePaths = {
            "authorityInstanceReference",
            "authorityInstanceReference.connectorInterface",
            "authorityInstanceReference.connector",
            "authorityInstanceReference.connector.functionGroups"
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
