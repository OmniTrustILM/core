package com.otilm.core.dao.repository;

import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import com.otilm.core.dao.entity.TrustedCertificate;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TrustedCertificateRepository extends JpaRepository<TrustedCertificate, UUID> {

    Optional<TrustedCertificate> findByCertificateUuid(UUID certificateUuid);

    boolean existsByCertificateUuid(UUID certificateUuid);

    @Query("SELECT t.certificateUuid FROM TrustedCertificate t WHERE t.certificateUuid IN :certificateUuids")
    List<UUID> findCertificateUuidsByCertificateUuidIn(@Param("certificateUuids") Collection<UUID> certificateUuids);

    List<TrustedCertificate> findAllByPlatformTrueOrPlatformRemovalPendingTrue();

    List<TrustedCertificate> findAllByPlatformStateIn(Collection<TrustedCertificatePlatformState> states);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE TrustedCertificate t
               SET t.platformState = :state, t.platformStateMessage = :message, t.platformStateCheckedAt = :checkedAt,
                   t.updatedAt = CURRENT_TIMESTAMP
             WHERE t.uuid = :uuid
            """)
    void updateObserved(@Param("uuid") UUID uuid, @Param("state") TrustedCertificatePlatformState state,
            @Param("message") String message, @Param("checkedAt") OffsetDateTime checkedAt);
}
