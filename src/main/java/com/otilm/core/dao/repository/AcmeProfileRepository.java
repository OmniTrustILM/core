package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AcmeProfileRepository extends SecurityFilterRepository<AcmeProfile, Long> {
    Optional<AcmeProfile> findByUuid(UUID uuid);

    boolean existsByName(String name);

    @EntityGraph(attributePaths = {"raProfile"})
    Optional<AcmeProfile> findByName(String name);

    List<AcmeProfile> findByRaProfile(RaProfile raProfile);

    /**
     * The profile under a row lock, for a decision that must not be taken on a copy read earlier: an edit can change
     * what a profile requires while a protocol request is still deciding against it.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT p FROM AcmeProfile p WHERE p.uuid = :uuid")
    Optional<AcmeProfile> findAndLockByUuid(UUID uuid);

    /**
     * Names of the profiles that accept the given secret as an External Account Binding key. Native because the column
     * is a PostgreSQL array and JPQL has no containment operator for one.
     */
    @Query(value = "SELECT p.name FROM {h-schema}acme_profile p WHERE :secretUuid = ANY(p.eab_secret_uuids)",
            nativeQuery = true)
    List<String> findNamesByEabSecretUuid(@Param("secretUuid") UUID secretUuid);
}
