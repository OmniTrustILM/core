package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface RaProfileRepository extends SecurityFilterRepository<RaProfile, UUID> {

    Optional<RaProfile> findByUuid(UUID uuid);

    /**
     * The RA Profile under a row lock, for a write decided on what the row holds: a change committed while the lock was
     * awaited is what the decision is taken on.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT r FROM RaProfile r WHERE r.uuid = :uuid")
    Optional<RaProfile> findWithLockByUuid(@Param("uuid") UUID uuid);

    /**
     * The RA Profiles with the EST Profile activated, each under a row lock, taken in one order. A row whose lock had
     * to be awaited is matched again as the other transaction committed it, so one that has been activated with another
     * EST Profile meanwhile is left out.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT r FROM RaProfile r WHERE r.estProfileUuid = :estProfileUuid ORDER BY r.uuid")
    List<RaProfile> findWithLockByEstProfileUuid(@Param("estProfileUuid") UUID estProfileUuid);

    /**
     * Loads an RA profile with its authority, connector, connector interface and the connector's function groups
     * eagerly. The function groups are fetched so callers that traverse the connector outside an active transaction
     * (e.g. request-attribute resolution under {@code Propagation.NOT_SUPPORTED}) do not depend on open-session-in-view
     * for the lazy collection.
     */
    @EntityGraph(attributePaths = {
            "authorityInstanceReference",
            "authorityInstanceReference.connectorInterface",
            "authorityInstanceReference.connector",
            "authorityInstanceReference.connector.functionGroups"})
    Optional<RaProfile> findWithAuthorityByUuid(UUID uuid);

    /** Scalar projection of the authority, read without managing the entity. */
    @Query("SELECT r.authorityInstanceReferenceUuid FROM RaProfile r WHERE r.uuid = :uuid")
    Optional<UUID> findAuthorityInstanceReferenceUuidByUuid(@Param("uuid") UUID uuid);

    Optional<RaProfile> findByName(String name);

    boolean existsByNameAndEstProfileUuidIsNotNull(String name);

    Optional<RaProfile> findByNameAndEnabledIsTrue(String name);

    Optional<RaProfile> findByUuidAndEnabledIsTrue(UUID uuid);

    List<RaProfile> findAllByAcmeProfileUuid(UUID acmeProfileUuid);

    List<RaProfile> findAllByScepProfileUuid(UUID scepProfileUuid);

    List<RaProfile> findAllByCmpProfileUuid(UUID cmpProfileUuid);

    List<RaProfile> findAllByEstProfileUuid(UUID estProfileUuid);

    boolean existsByEstProfileUuid(UUID estProfileUuid);

    List<RaProfile> findAllByUuidIn(List<UUID> uuids);
}
