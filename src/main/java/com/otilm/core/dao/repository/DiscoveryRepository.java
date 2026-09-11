package com.otilm.core.dao.repository;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface DiscoveryRepository extends SecurityFilterRepository<Discovery, UUID> {

    Optional<Discovery> findByUuid(UUID uuid);

    /**
     * Pessimistic-write variant of {@link #findByUuid} for read-modify-write transitions on the run row. Issues
     * {@code SELECT ... FOR UPDATE}; must be called inside an active transaction, otherwise the lock is released
     * immediately on query completion.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT d FROM Discovery d WHERE d.uuid = :uuid")
    Optional<Discovery> findWithLockByUuid(@Param("uuid") UUID uuid);

    @EntityGraph(attributePaths = {"triggers"})
    Discovery findWithTriggersByUuid(UUID uuid);

    Optional<Discovery> findByName(String name);

    @Query("SELECT DISTINCT connectorName FROM Discovery ")
    List<String> findDistinctConnectorName();

    /**
     * The run's connector interface, read as a scalar so dispatch can pick an adapter without pulling the run into the
     * persistence context. Empty both for a run that does not exist and for one with no association — the two route the
     * same way, to v1.
     */
    @Query("SELECT d.connectorInterfaceUuid FROM Discovery d WHERE d.uuid = :uuid")
    Optional<UUID> findConnectorInterfaceUuid(@Param("uuid") UUID uuid);

    @Modifying
    @Query("UPDATE Discovery d SET d.message = :message, d.updated = CURRENT_TIMESTAMP WHERE d.uuid = :uuid")
    void updateMessage(@Param("uuid") UUID uuid, @Param("message") String message);

    /**
     * Clears the interface reference from every run holding one of these interfaces. See
     * {@code DiscoveryWriter#releaseConnectorInterfaces}, its only caller, for why.
     *
     * @return how many runs were released
     */
    @Modifying
    @Query("UPDATE Discovery d SET d.connectorInterfaceUuid = NULL, d.updated = CURRENT_TIMESTAMP "
            + "WHERE d.connectorInterfaceUuid IN :interfaceUuids")
    int releaseConnectorInterfaces(@Param("interfaceUuids") Collection<UUID> interfaceUuids);

    /**
     * Uuids of v2 runs (interface association present) still in one of {@code statuses} whose agenda is empty and that
     * were created before {@code threshold} — the tick engine can never drive them again. No row locking: the caller
     * re-asserts the condition under a per-run pessimistic lock before acting.
     *
     * <p>
     * The grace window is keyed to run <em>creation</em>, so it only covers the initiate gap — see
     * {@link com.otilm.core.service.writer.discovery.DiscoveryWorkWriter} for the empty-agenda rule that makes this
     * safe for live runs.
     * </p>
     */
    @Query("SELECT d.uuid FROM Discovery d WHERE d.connectorInterfaceUuid IS NOT NULL AND d.status IN :statuses "
            + "AND d.created < :threshold "
            + "AND NOT EXISTS (SELECT w FROM DiscoveryWork w WHERE w.discoveryUuid = d.uuid)")
    List<UUID> findWorkLostRunUuids(@Param("statuses") Collection<DiscoveryStatus> statuses,
            @Param("threshold") OffsetDateTime threshold, Pageable pageable);

    /**
     * Uuids of v2 runs still {@code STOPPED} that were stopped before {@code threshold} — runs whose resume window has
     * expired. Constrained to {@code STOPPED} in the query so a resumed run can never match on a leftover
     * {@code stoppedAt} alone. No row locking: see {@link #findWorkLostRunUuids}.
     */
    @Query("SELECT d.uuid FROM Discovery d WHERE d.connectorInterfaceUuid IS NOT NULL "
            + "AND d.status = com.otilm.api.model.core.discovery.DiscoveryStatus.STOPPED "
            + "AND d.stoppedAt < :threshold")
    List<UUID> findExpiredStoppedRunUuids(@Param("threshold") OffsetDateTime threshold, Pageable pageable);
}
