package com.otilm.core.dao.repository.scep;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScepProfileRepository extends SecurityFilterRepository<ScepProfile, Long> {
    Optional<ScepProfile> findByUuid(UUID uuid);

    boolean existsByName(String name);

    Optional<ScepProfile> findByName(String name);

    List<ScepProfile> findByRaProfile(RaProfile raProfile);

    List<ScepProfile> findByIntuneEnabled(boolean intuneEnabled);

    @Modifying
    @Query("UPDATE ScepProfile sp SET sp.caCertificateUuid = NULL WHERE sp.caCertificateUuid = ?1")
    void clearCaCertificateReference(UUID caCertificateUuid);

    @Modifying
    @Query("UPDATE ScepProfile sp SET sp.caCertificateUuid = NULL WHERE sp.caCertificateUuid IN ?1")
    void clearCaCertificateReferenceIn(List<UUID> caCertificateUuids);
}
