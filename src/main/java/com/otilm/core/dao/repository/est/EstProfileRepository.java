package com.otilm.core.dao.repository.est;

import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface EstProfileRepository extends SecurityFilterRepository<EstProfile, UUID> {

    Optional<EstProfile> findByName(String name);

    Optional<EstProfile> findBySystemDefaultTrue();

    List<EstProfile> findAllByRaProfileUuid(UUID raProfileUuid);

    List<EstProfile> findAllByKeyRecoveryTokenProfileUuid(UUID tokenProfileUuid);

    /**
     * The profile under a row lock, for a write of the whole row: a change committed while the lock was awaited is read
     * rather than overwritten with an older copy.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT p FROM EstProfile p WHERE p.uuid = :uuid")
    Optional<EstProfile> findWithLockByUuid(@Param("uuid") UUID uuid);

    /**
     * The profiles that accept the given secret as a basic-auth credential. Native because the column is a PostgreSQL
     * array and JPQL has no containment operator for one.
     */
    @Query(value = "SELECT p.* FROM {h-schema}est_profile p WHERE :secretUuid = ANY(p.basic_credential_secret_uuids)",
            nativeQuery = true)
    List<EstProfile> findByBasicCredentialSecretUuid(@Param("secretUuid") UUID secretUuid);

    /**
     * The secrets the profile accepts as basic-auth credentials, read without the profile, so no copy of it stays in
     * the persistence context to be taken for the row a later locked read returns.
     */
    @Query(value = "SELECT unnest(p.basic_credential_secret_uuids) FROM {h-schema}est_profile p WHERE p.uuid = :uuid",
            nativeQuery = true)
    List<UUID> findBasicCredentialSecretUuids(@Param("uuid") UUID uuid);

    /** Clears the system default flag, whichever profile holds it. */
    @Modifying
    @Query("UPDATE EstProfile p SET p.systemDefault = FALSE, p.updated = CURRENT_TIMESTAMP "
            + "WHERE p.systemDefault = TRUE")
    int clearSystemDefault();

    /** Clears the system default flag of every profile but the one that is about to hold it. */
    @Modifying
    @Query("UPDATE EstProfile p SET p.systemDefault = FALSE, p.updated = CURRENT_TIMESTAMP "
            + "WHERE p.systemDefault = TRUE AND p.uuid <> :uuid")
    int clearSystemDefaultExcept(@Param("uuid") UUID uuid);

    /**
     * Drops the certificates from the trusted CA list of every profile that lists any of them, keeping the rest in
     * their order, and leaves the other profiles untouched, in one statement however many certificates a bulk delete
     * passes. Native because JPQL cannot rebuild an array column, so pending changes are flushed first: Hibernate
     * cannot tell which tables SQL it does not parse reads.
     */
    @Modifying(flushAutomatically = true)
    @Query(value = """
            UPDATE {h-schema}est_profile p
               SET trusted_ca_certificate_uuids = ARRAY(
                       SELECT t.u
                         FROM unnest(p.trusted_ca_certificate_uuids) WITH ORDINALITY AS t(u, o)
                        WHERE t.u NOT IN (:certificateUuids)
                        ORDER BY t.o),
                   i_upd = CURRENT_TIMESTAMP
             WHERE EXISTS (SELECT 1
                             FROM unnest(p.trusted_ca_certificate_uuids) AS x(u)
                            WHERE x.u IN (:certificateUuids))
            """, nativeQuery = true)
    int removeTrustedCaCertificates(@Param("certificateUuids") List<UUID> certificateUuids);
}
