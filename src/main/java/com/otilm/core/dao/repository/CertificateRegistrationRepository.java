package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateRegistration;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRegistrationRepository extends JpaRepository<CertificateRegistration, UUID> {

    Optional<CertificateRegistration> findByCertificateUuid(UUID certificateUuid);

    /**
     * Pessimistic-write variant ({@code SELECT ... FOR UPDATE}) for the register-bound issue path, so concurrent
     * issues serialize on the binding row. Must run in a transaction, and the lock must not span the connector
     * call — the caller consumes the binding while holding it, then releases before going upstream.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CertificateRegistration> findAndLockByCertificateUuid(UUID certificateUuid);

    /**
     * Creates the binding, or replaces its meta when one already exists (async completion superseding the 202
     * handle). Atomic on the unique {@code certificate_uuid} — a concurrent loser updates instead of aborting.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}certificate_registration (uuid, certificate_uuid, meta)
            VALUES (:uuid, :certificateUuid, :meta)
            ON CONFLICT (certificate_uuid) DO UPDATE SET meta = EXCLUDED.meta, i_upd = now()
            """, nativeQuery = true)
    void upsert(@Param("uuid") UUID uuid,
                @Param("certificateUuid") UUID certificateUuid,
                @Param("meta") String meta);

    @Modifying
    @Query("DELETE FROM CertificateRegistration r WHERE r.certificateUuid = :certificateUuid")
    void deleteByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);
}
