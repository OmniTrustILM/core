package com.otilm.core.dao.repository.est;

import com.otilm.core.dao.entity.est.EstRequestClaim;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface EstRequestClaimRepository extends JpaRepository<EstRequestClaim, UUID> {

    /** A claim and the certificate that it links, null while its request has stored none. */
    interface ClaimLink {

        UUID getUuid();

        UUID getCertificateUuid();
    }

    /**
     * Inserts the claim, or takes over an existing one that links a certificate or is older than {@code expirySeconds},
     * unlinking it. Atomic on the unique key, so of several concurrent callers exactly one gets {@code 1}; a loser gets
     * {@code 0} without a constraint violation.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}est_request_claim AS c
                (uuid, est_profile_uuid, ra_profile_uuid, operation, request_key, claimed_at)
            VALUES (:uuid, :estProfileUuid, :raProfileUuid, :operation, :requestKey, now())
            ON CONFLICT (est_profile_uuid, ra_profile_uuid, operation, request_key)
            DO UPDATE SET uuid = EXCLUDED.uuid, claimed_at = EXCLUDED.claimed_at, certificate_uuid = NULL
            WHERE c.certificate_uuid IS NOT NULL
                OR c.claimed_at < now() - CAST(:expirySeconds AS integer) * INTERVAL '1 second'
            """, nativeQuery = true)
    int claim(@Param("uuid") UUID uuid, @Param("estProfileUuid") UUID estProfileUuid,
            @Param("raProfileUuid") UUID raProfileUuid, @Param("operation") String operation,
            @Param("requestKey") String requestKey, @Param("expirySeconds") long expirySeconds);

    /**
     * Links the certificate to the claim, which the row lock keeps from being taken over until the caller's transaction
     * ends. Flushes first, so that the certificate row the link refers to exists.
     *
     * @return {@code 0} when the claim was taken over
     */
    @Modifying(flushAutomatically = true)
    @Query(value = "UPDATE {h-schema}est_request_claim SET certificate_uuid = :certificateUuid WHERE uuid = :uuid",
            nativeQuery = true)
    int link(@Param("uuid") UUID uuid, @Param("certificateUuid") UUID certificateUuid);

    @Query("""
            SELECT c.uuid AS uuid, c.certificateUuid AS certificateUuid FROM EstRequestClaim c
            WHERE c.estProfileUuid = :estProfileUuid AND c.raProfileUuid = :raProfileUuid
                AND c.operation = :operation AND c.requestKey = :requestKey
            """)
    Optional<ClaimLink> findLink(@Param("estProfileUuid") UUID estProfileUuid,
            @Param("raProfileUuid") UUID raProfileUuid, @Param("operation") EstRequestClaim.Operation operation,
            @Param("requestKey") String requestKey);

    @Modifying
    @Query(value = "DELETE FROM {h-schema}est_request_claim WHERE uuid = :uuid AND certificate_uuid IS NULL",
            nativeQuery = true)
    int release(@Param("uuid") UUID uuid);
}
