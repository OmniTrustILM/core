package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRegistrationAuthorizationRepository extends JpaRepository<CertificateRegistrationAuthorization, UUID> {

    Optional<CertificateRegistrationAuthorization> findByCertificateUuid(UUID certificateUuid);

    /** Presence check for the fire guards — avoids loading the secret-bearing row just to test existence. */
    boolean existsByCertificateUuid(UUID certificateUuid);

    /** Projection over the non-secret detail fields, so the certificate-detail read never loads the challenge column. */
    interface RegistrationDetailView {
        RegistrationState getState();

        OffsetDateTime getExpiresAt();

        int getFailedAttempts();
    }

    /** Reads only the detail fields (no challenge ciphertext) for the read-only certificate-detail registration block. */
    Optional<RegistrationDetailView> findDetailByCertificateUuid(UUID certificateUuid);

    /**
     * Pessimistic-write finder ({@code SELECT ... FOR UPDATE}) so a concurrent verify / failed-attempt update
     * serializes on the authorization row. Must run in a transaction; the lock must not span an external call.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CertificateRegistrationAuthorization> findAndLockByCertificateUuid(UUID certificateUuid);

    @Modifying
    @Query("DELETE FROM CertificateRegistrationAuthorization r WHERE r.certificateUuid = :certificateUuid")
    void deleteByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);

    @Modifying
    @Query("UPDATE CertificateRegistrationAuthorization r SET r.state = :state, r.updated = CURRENT_TIMESTAMP WHERE r.certificateUuid = :certificateUuid")
    void updateStateByCertificateUuid(@Param("certificateUuid") UUID certificateUuid, @Param("state") RegistrationState state);
}
