package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateRenewalLocation;
import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
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
public interface CertificateRenewalLocationRepository extends JpaRepository<CertificateRenewalLocation, UUID> {

    List<CertificateRenewalLocation> findByCertificateUuid(UUID certificateUuid);

    Optional<CertificateRenewalLocation> findByCertificateUuidAndLocationUuid(UUID certificateUuid, UUID locationUuid);

    /**
     * Locks the row without waiting: answers nothing when another transaction holds it, which may be a transaction this
     * thread suspended.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout",
            value = CertificateRenewalInfoRepository.SKIP_LOCKED))
    @Query("""
            SELECT r FROM CertificateRenewalLocation r
             WHERE r.certificateUuid = :certificateUuid AND r.locationUuid = :locationUuid
            """)
    Optional<CertificateRenewalLocation> findAndLockSkipLocked(@Param("certificateUuid") UUID certificateUuid,
            @Param("locationUuid") UUID locationUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT r FROM CertificateRenewalLocation r
             WHERE r.certificateUuid = :certificateUuid AND r.locationUuid = :locationUuid
            """)
    Optional<CertificateRenewalLocation> findAndLock(@Param("certificateUuid") UUID certificateUuid,
            @Param("locationUuid") UUID locationUuid);

    /** Clears the failure counters of the certificates' location rows not yet completed. */
    @Modifying(flushAutomatically = true)
    @Query(value = """
            UPDATE {h-schema}certificate_renewal_location
               SET attempt = 0,
                   not_before = NULL
             WHERE certificate_uuid IN (:certificateUuids)
               AND completed_at IS NULL
            """, nativeQuery = true)
    int resetOpenAttempts(@Param("certificateUuids") Collection<UUID> certificateUuids);
}
