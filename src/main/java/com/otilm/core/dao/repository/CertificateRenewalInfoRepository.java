package com.otilm.core.dao.repository;

import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateRenewalInfoRepository extends JpaRepository<CertificateRenewalInfo, UUID> {

    /**
     * The certificate {@code c}, joined to its RA profile {@code rp}, authority {@code a} and connector interface
     * {@code ci}, has its renewal information refreshed: issued, not archived, not expired at {@code :now}, no issued
     * successor, the RA profile uses the authority's renewal information and the connector advertises it.
     */
    String REFRESH_ELIGIBLE = """
            c.state = 'ISSUED'
            AND c.archived = false
            AND c.not_after > :now
            AND rp.renewal_use_authority_info = true
            AND 'CERTIFICATE_RENEWAL_INFO' = ANY (ci.features)
            AND NOT EXISTS (SELECT 1
                              FROM {h-schema}certificate_relation rel
                              JOIN {h-schema}certificate s ON s.uuid = rel.successor_certificate_uuid
                             WHERE rel.predecessor_certificate_uuid = c.uuid
                               AND s.state = 'ISSUED')
            """;

    String REFRESH_ELIGIBLE_JOINS = """
            {h-schema}certificate c
            JOIN {h-schema}ra_profile rp ON rp.uuid = c.ra_profile_uuid
            JOIN {h-schema}authority_instance_reference a ON a.uuid = rp.authority_instance_ref_uuid
            JOIN {h-schema}connector_interface ci ON ci.uuid = a.connector_interface_uuid
            """;

    /**
     * Gives eligible certificates without refresh state a first refresh time between {@code :now} and
     * {@code :spreadSeconds} later. A certificate marked unsupported keeps waiting for its re-check.
     */
    String ENROL_HEAD = """
            INSERT INTO {h-schema}certificate_renewal_info AS r
                (uuid, certificate_uuid, updated_at, advanced, next_refresh_at, refresh_attempt, refresh_unsupported)
            SELECT gen_random_uuid(), c.uuid, :now, false,
                   CAST(:now AS TIMESTAMP WITH TIME ZONE) + random() * :spreadSeconds * INTERVAL '1 second', 0, false
              FROM\s""" + REFRESH_ELIGIBLE_JOINS + """
             LEFT JOIN {h-schema}certificate_renewal_info existing ON existing.certificate_uuid = c.uuid
            WHERE (existing.uuid IS NULL
                   OR existing.next_refresh_at IS NULL AND existing.refresh_unsupported = false)
              AND\s""" + REFRESH_ELIGIBLE;

    String ENROL_TAIL = """
            ON CONFLICT (certificate_uuid) DO UPDATE
               SET next_refresh_at = EXCLUDED.next_refresh_at,
                   refresh_attempt = 0,
                   refresh_unsupported = false
             WHERE r.next_refresh_at IS NULL AND r.refresh_unsupported = false
            """;

    /** Hibernate's lock timeout that skips locked rows. */
    String SKIP_LOCKED = "-2";

    /**
     * The policy windows {@code w} of the issued, unexpired, non-archived certificates of the RA profile, placed as
     * {@code PolicyWindow} places them: whole milliseconds of the lifetime, added as an exact duration to the start
     * read as a point in time.
     */
    String POLICY_WINDOWS = """
            (SELECT v.certificate_uuid,
                    v.not_before + (v.lifetime_millis * :startPercent / 100) * INTERVAL '1 millisecond' AS window_start,
                    v.not_before + (v.lifetime_millis * :endPercent / 100) * INTERVAL '1 millisecond' AS window_end
               FROM (SELECT c.uuid AS certificate_uuid,
                            CAST(c.not_before AS TIMESTAMP WITH TIME ZONE) AS not_before,
                            ROUND((EXTRACT(EPOCH FROM CAST(c.not_after AS TIMESTAMP WITH TIME ZONE))
                                - EXTRACT(EPOCH FROM CAST(c.not_before AS TIMESTAMP WITH TIME ZONE)))
                                * 1000)::bigint AS lifetime_millis
                       FROM {h-schema}certificate c
                      WHERE c.ra_profile_uuid = :raProfileUuid
                        AND c.state = 'ISSUED'
                        AND c.archived = false
                        AND c.not_before IS NOT NULL
                        AND c.not_after > c.not_before
                        AND c.not_after > :now) v) w
            """;

    String RESET_REFRESH = """
            UPDATE {h-schema}certificate_renewal_info r
               SET next_refresh_at = NULL,
                   refresh_attempt = 0,
                   refresh_unsupported = false
            """;

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT r FROM CertificateRenewalInfo r WHERE r.certificateUuid = :certificateUuid")
    Optional<CertificateRenewalInfo> findAndLockByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);

    /**
     * Locks the certificate's row without waiting: answers nothing when another transaction holds the lock, which may
     * be a transaction this thread suspended.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = SKIP_LOCKED))
    @Query("SELECT r FROM CertificateRenewalInfo r WHERE r.certificateUuid = :certificateUuid")
    Optional<CertificateRenewalInfo> findAndLockByCertificateUuidSkipLocked(
            @Param("certificateUuid") UUID certificateUuid);

    Optional<CertificateRenewalInfo> findByCertificateUuid(UUID certificateUuid);

    List<CertificateRenewalInfo> findByCertificateUuidIn(Collection<UUID> certificateUuids);

    /**
     * Answers the certificate's RA profile when its renewal information is refreshed, holding that profile's row in
     * share mode, so that a change of the profile waits for the caller's transaction and the caller sees a committed
     * change.
     */
    @Query(value = "SELECT rp.uuid FROM\s" + REFRESH_ELIGIBLE_JOINS + """
            WHERE c.uuid = :certificateUuid
              AND\s""" + REFRESH_ELIGIBLE + """
            FOR SHARE OF rp
            """, nativeQuery = true)
    Optional<UUID> lockRaProfileWhenRefreshEligible(@Param("certificateUuid") UUID certificateUuid,
            @Param("now") Instant now);

    /** Creates an empty row for the certificate unless one exists, so that the row can be locked. */
    @Modifying(flushAutomatically = true)
    @Query(value = """
            INSERT INTO {h-schema}certificate_renewal_info (uuid, certificate_uuid, updated_at, advanced)
            VALUES (:uuid, :certificateUuid, :now, false)
            ON CONFLICT (certificate_uuid) DO NOTHING
            """, nativeQuery = true)
    void insertIfAbsent(@Param("uuid") UUID uuid, @Param("certificateUuid") UUID certificateUuid,
            @Param("now") Instant now);

    /**
     * Sets the policy window on the issued, unexpired, non-archived certificates of the RA profile whose window is
     * missing or came from the policy, clearing the automatic renewal time and failure counters of each changed row.
     * Answers the windows that changed.
     */
    // Not @Modifying: Spring Data runs a @Modifying query as an update count and would drop the RETURNING rows.
    @Query(value = """
            INSERT INTO {h-schema}certificate_renewal_info AS r
                (uuid, certificate_uuid, window_start, window_end, explanation_url, source, updated_at, advanced)
            SELECT gen_random_uuid(), w.certificate_uuid, w.window_start, w.window_end, NULL, 'POLICY', :now, false
              FROM\s""" + POLICY_WINDOWS + """
             WHERE w.window_end > w.window_start
            ON CONFLICT (certificate_uuid) DO UPDATE
               SET window_start = EXCLUDED.window_start,
                   window_end = EXCLUDED.window_end,
                   explanation_url = NULL,
                   source = 'POLICY',
                   updated_at = EXCLUDED.updated_at,
                   advanced = false,
                   renew_at = NULL,
                   renew_attempt = 0,
                   renew_not_before = NULL
             WHERE (r.source IS NULL OR r.source = 'POLICY')
               AND (r.window_start IS DISTINCT FROM EXCLUDED.window_start
                    OR r.window_end IS DISTINCT FROM EXCLUDED.window_end
                    OR r.source IS NULL)
            RETURNING r.certificate_uuid AS certificateUuid, r.window_start AS windowStart, r.window_end AS windowEnd
            """, nativeQuery = true)
    List<PolicyWindowChange> upsertPolicyWindows(@Param("raProfileUuid") UUID raProfileUuid,
            @Param("startPercent") int startPercent, @Param("endPercent") int endPercent, @Param("now") Instant now);

    /**
     * Clears the policy window of the RA profile's certificates whose new policy window would be empty, with their
     * automatic renewal time and failure counters, as the per-certificate writer removes it. Answers the certificates
     * that lost one.
     */
    // Not @Modifying: Spring Data runs a @Modifying query as an update count and would drop the RETURNING rows.
    @Query(value = """
            UPDATE {h-schema}certificate_renewal_info r
               SET window_start = NULL,
                   window_end = NULL,
                   explanation_url = NULL,
                   source = NULL,
                   updated_at = :now,
                   advanced = false,
                   renew_at = NULL,
                   renew_attempt = 0,
                   renew_not_before = NULL
              FROM\s""" + POLICY_WINDOWS + """
             WHERE r.certificate_uuid = w.certificate_uuid
               AND r.source = 'POLICY'
               AND w.window_end <= w.window_start
            RETURNING r.certificate_uuid
            """, nativeQuery = true)
    List<UUID> clearEmptyPolicyWindows(@Param("raProfileUuid") UUID raProfileUuid,
            @Param("startPercent") int startPercent, @Param("endPercent") int endPercent, @Param("now") Instant now);

    /**
     * Clears the policy windows of the certificates of the RA profile, with their automatic renewal time and failure
     * counters; the rows stay. Answers the certificates that lost one.
     */
    // Not @Modifying: Spring Data runs a @Modifying query as an update count and would drop the RETURNING rows.
    @Query(value = """
            UPDATE {h-schema}certificate_renewal_info r
               SET window_start = NULL,
                   window_end = NULL,
                   explanation_url = NULL,
                   source = NULL,
                   updated_at = :now,
                   advanced = false,
                   renew_at = NULL,
                   renew_attempt = 0,
                   renew_not_before = NULL
              FROM {h-schema}certificate c
             WHERE c.uuid = r.certificate_uuid
               AND c.ra_profile_uuid = :raProfileUuid
               AND r.source = 'POLICY'
            RETURNING r.certificate_uuid
            """, nativeQuery = true)
    List<UUID> clearPolicyWindows(@Param("raProfileUuid") UUID raProfileUuid, @Param("now") Instant now);

    /** Sets the refresh state of the certificate's row. */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}certificate_renewal_info
               SET next_refresh_at = :nextRefreshAt,
                   refresh_attempt = :attempt,
                   refresh_unsupported = :unsupported
             WHERE certificate_uuid = :certificateUuid
            """, nativeQuery = true)
    int updateRefreshState(@Param("certificateUuid") UUID certificateUuid,
            @Param("nextRefreshAt") Instant nextRefreshAt, @Param("attempt") int attempt,
            @Param("unsupported") boolean unsupported);

    /** Counts one more failed refresh of the certificate's row; answers the new count, or nothing without a row. */
    // Not @Modifying: Spring Data runs a @Modifying query as an update count and would drop the RETURNING value.
    @Query(value = """
            UPDATE {h-schema}certificate_renewal_info
               SET refresh_attempt = refresh_attempt + 1,
                   refresh_unsupported = false
             WHERE certificate_uuid = :certificateUuid
            RETURNING refresh_attempt
            """, nativeQuery = true)
    Integer incrementRefreshAttempt(@Param("certificateUuid") UUID certificateUuid);

    /** Sets the next refresh time of the certificates' rows, leaving the rest of their refresh state. */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}certificate_renewal_info
               SET next_refresh_at = :nextRefreshAt
             WHERE certificate_uuid IN (:certificateUuids)
            """, nativeQuery = true)
    int updateNextRefreshAt(@Param("certificateUuids") Collection<UUID> certificateUuids,
            @Param("nextRefreshAt") Instant nextRefreshAt);

    /** Enrols up to {@code limit} eligible certificates; answers how many. */
    @Modifying(flushAutomatically = true)
    @Query(value = ENROL_HEAD + " LIMIT :limit " + ENROL_TAIL, nativeQuery = true)
    int enrolEligible(@Param("now") Instant now, @Param("spreadSeconds") int spreadSeconds, @Param("limit") int limit);

    /** Enrols the certificate when it is eligible; answers whether it was. */
    @Modifying(flushAutomatically = true)
    @Query(value = ENROL_HEAD + " AND c.uuid = :certificateUuid " + ENROL_TAIL, nativeQuery = true)
    int enrolCertificate(@Param("certificateUuid") UUID certificateUuid, @Param("now") Instant now,
            @Param("spreadSeconds") int spreadSeconds);

    /** Enrols the eligible certificates of the RA profile; answers how many. */
    @Modifying(flushAutomatically = true)
    @Query(value = ENROL_HEAD + " AND c.ra_profile_uuid = :raProfileUuid " + ENROL_TAIL, nativeQuery = true)
    int enrolRaProfile(@Param("raProfileUuid") UUID raProfileUuid, @Param("now") Instant now,
            @Param("spreadSeconds") int spreadSeconds);

    /** Clears the refresh state of the certificates. */
    @Modifying(flushAutomatically = true)
    @Query(value = RESET_REFRESH + " WHERE r.certificate_uuid IN (:certificateUuids)", nativeQuery = true)
    int resetRefresh(@Param("certificateUuids") Collection<UUID> certificateUuids);

    /** Clears the refresh state of the certificates of the RA profile. */
    @Modifying(flushAutomatically = true)
    @Query(value = RESET_REFRESH + """
              FROM {h-schema}certificate c
             WHERE c.uuid = r.certificate_uuid
               AND c.ra_profile_uuid = :raProfileUuid
            """, nativeQuery = true)
    int resetRaProfileRefresh(@Param("raProfileUuid") UUID raProfileUuid);

    /** Clears the refresh state of the predecessors of the certificate once it is issued. */
    @Modifying(flushAutomatically = true)
    @Query(value = RESET_REFRESH + """
              FROM {h-schema}certificate_relation rel
              JOIN {h-schema}certificate s ON s.uuid = rel.successor_certificate_uuid
             WHERE rel.successor_certificate_uuid = :certificateUuid
               AND s.state = 'ISSUED'
               AND r.certificate_uuid = rel.predecessor_certificate_uuid
            """, nativeQuery = true)
    int resetPredecessorRefresh(@Param("certificateUuid") UUID certificateUuid);

    /** Clears the refresh state of due certificates that are no longer eligible; answers how many. */
    @Modifying(flushAutomatically = true)
    @Query(value = RESET_REFRESH + """
            WHERE r.next_refresh_at <= :now
              AND NOT EXISTS (SELECT 1 FROM\s""" + REFRESH_ELIGIBLE_JOINS + " WHERE c.uuid = r.certificate_uuid AND "
            + REFRESH_ELIGIBLE + ")", nativeQuery = true)
    int resetIneligibleDue(@Param("now") Instant now);

    /**
     * Claims the due eligible certificates, at most {@code maxPerAuthority} of each authority, the longest due first:
     * their next refresh moves to {@code leaseUntil}, so that a claim nobody completes is claimed again then. Rows
     * another transaction holds are skipped and claimed by a later sweep, so the claim never waits for a writer.
     */
    // Not @Modifying: Spring Data runs a @Modifying query as an update count and would drop the RETURNING rows.
    @Query(value = """
            WITH locked AS (
                SELECT r.certificate_uuid, r.next_refresh_at, c.ra_profile_uuid,
                       rp.authority_instance_ref_uuid AS authority_uuid
                  FROM\s""" + REFRESH_ELIGIBLE_JOINS + """
             JOIN {h-schema}certificate_renewal_info r ON r.certificate_uuid = c.uuid
            WHERE r.next_refresh_at <= :now
              AND\s""" + REFRESH_ELIGIBLE + """
            FOR UPDATE OF r SKIP LOCKED
            ), due AS (
                SELECT certificate_uuid, ra_profile_uuid, authority_uuid,
                       ROW_NUMBER() OVER (PARTITION BY authority_uuid ORDER BY next_refresh_at, certificate_uuid)
                           AS position
                  FROM locked
            )
            UPDATE {h-schema}certificate_renewal_info r
               SET next_refresh_at = :leaseUntil
              FROM due
             WHERE r.certificate_uuid = due.certificate_uuid
               AND due.position <= :maxPerAuthority
            RETURNING r.certificate_uuid AS certificateUuid, due.ra_profile_uuid AS raProfileUuid,
                      due.authority_uuid AS authorityUuid
            """, nativeQuery = true)
    List<RefreshClaim> claimDue(@Param("now") Instant now, @Param("maxPerAuthority") int maxPerAuthority,
            @Param("leaseUntil") Instant leaseUntil);

    /** The certificates of the RA profile whose window came from the given source. */
    @Query("""
            SELECT r.certificateUuid FROM CertificateRenewalInfo r JOIN r.certificate c
             WHERE c.raProfileUuid = :raProfileUuid AND r.source = :source
            """)
    List<UUID> findCertificateUuidsByRaProfileAndSource(@Param("raProfileUuid") UUID raProfileUuid,
            @Param("source") RenewalWindowSource source);

    /** A certificate claimed for a refresh, with the RA profile and authority it is asked through. */
    interface RefreshClaim {

        UUID getCertificateUuid();

        UUID getRaProfileUuid();

        UUID getAuthorityUuid();
    }

    /** A policy window as the statement that changed it returned it. */
    interface PolicyWindowChange {

        UUID getCertificateUuid();

        Instant getWindowStart();

        Instant getWindowEnd();
    }
}
