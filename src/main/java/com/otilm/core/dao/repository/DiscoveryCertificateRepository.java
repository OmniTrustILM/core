package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface DiscoveryCertificateRepository extends SecurityFilterRepository<DiscoveryCertificate, Long> {
    Optional<DiscoveryCertificate> findByUuid(UUID uuid);

    Long deleteByDiscovery(Discovery history);

    List<DiscoveryCertificate> findByDiscovery(Discovery history, Pageable pagable);

    @EntityGraph(attributePaths = {"certificateContent"})
    List<DiscoveryCertificate> findByDiscoveryUuidAndNewlyDiscovered(UUID discoveryUuid, boolean newlyDiscovered,
            Pageable pageable);

    /**
     * The v2 processing claim: certificate contents a run still has work for, oldest first, each with its row count.
     *
     * <p>
     * Claims on a recorded outcome, not on {@code processed}: a row the pipeline never reached keeps
     * {@code processed = false} with only its reason written, so claiming on {@code processed} alone would hand it back
     * forever.
     */
    @Query("SELECT dc.certificateContentId, COUNT(dc) FROM DiscoveryCertificate dc "
            + "WHERE dc.discoveryUuid = :discoveryUuid AND dc.newlyDiscovered = true AND dc.processed = false "
            + "AND dc.processedError IS NULL "
            + "GROUP BY dc.certificateContentId ORDER BY MIN(dc.created), dc.certificateContentId")
    List<Object[]> findPendingContentWeights(@Param("discoveryUuid") UUID discoveryUuid, Pageable pageable);

    /** Every pending row of the given contents, so a claimed group is always whole. */
    @EntityGraph(attributePaths = {"certificateContent"})
    List<DiscoveryCertificate> findByDiscoveryUuidAndCertificateContentIdInAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(
            UUID discoveryUuid, Collection<Long> certificateContentIds);

    long countByDiscoveryUuidAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(UUID discoveryUuid);

    /** The same count narrowed to one batch's rows — what decides whether a failed batch will be tried again. */
    long countByUuidInAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(Collection<UUID> uuids);

    /** Whether any row of the run recorded a reason it could not be imported — what makes a run end WARNING. */
    boolean existsByDiscoveryUuidAndProcessedErrorIsNotNull(UUID discoveryUuid);

    /**
     * Which of {@code refs} the run has already staged.
     */
    @Query("SELECT dc.uniqueRef FROM DiscoveryCertificate dc "
            + "WHERE dc.discoveryUuid = :discoveryUuid AND dc.uniqueRef IN :refs")
    List<String> findStagedRefs(@Param("discoveryUuid") UUID discoveryUuid, @Param("refs") Collection<String> refs);

    Long countByDiscovery(Discovery history);

    Long countByDiscoveryAndNewlyDiscovered(Discovery history, boolean newlyDiscovered);

    List<DiscoveryCertificate> findByCertificateContent(CertificateContent certificateContent);

    /**
     * Batched deliberately: every row of a content group shares one outcome and one reason, so a group collapses to a
     * single statement rather than one transaction per row.
     */
    @Modifying
    @Query("UPDATE DiscoveryCertificate dc SET dc.processed = true, dc.processedError = :processedError, "
            + "dc.updated = CURRENT_TIMESTAMP WHERE dc.uuid IN :uuids")
    void markProcessed(@Param("uuids") Collection<UUID> uuids, @Param("processedError") String processedError);

    @Modifying
    @Query("UPDATE DiscoveryCertificate dc SET dc.processedError = :processedError, "
            + "dc.updated = CURRENT_TIMESTAMP WHERE dc.uuid IN :uuids")
    void updateProcessedError(@Param("uuids") Collection<UUID> uuids, @Param("processedError") String processedError);

}
