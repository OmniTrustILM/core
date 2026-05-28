package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SigningProfileVersionRepository extends JpaRepository<SigningProfileVersion, UUID> {

    @EntityGraph(attributePaths = {
            "certificate",
            "certificate.certificateContent",
            "certificate.key",
            "certificate.key.items",
    })
    Optional<SigningProfileVersion> findWithAssociationsBySigningProfileUuidAndVersion(UUID signingProfileUuid, int version);

    Optional<SigningProfileVersion> findBySigningProfileUuidAndVersion(UUID signingProfileUuid, int version);

    @Modifying
    @Query("DELETE FROM SigningProfileVersion v WHERE v.signingProfileUuid = :signingProfileUuid")
    void deleteAllBySigningProfileUuid(UUID signingProfileUuid);

    /**
     * Acquires a PostgreSQL transaction-scoped advisory lock keyed on {@code lockKey}.
     * The lock is automatically released when the surrounding transaction commits or rolls back.
     * Used to serialize the version-bump decision in {@code updateSigningProfile}.
     */
    @Query(value = "SELECT 1 FROM pg_advisory_xact_lock(hashtext(:lockKey))", nativeQuery = true)
    void acquireAdvisoryLock(@Param("lockKey") String lockKey);
}
