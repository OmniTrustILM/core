package com.otilm.core.dao.repository.cmp;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CmpProfileRepository extends SecurityFilterRepository<CmpProfile, Long> {
    Optional<CmpProfile> findByUuid(UUID uuid);

    boolean existsByName(String name);

    Optional<CmpProfile> findByName(String name);

    List<CmpProfile> findByRaProfile(RaProfile raProfile);

    @Modifying
    @Query("UPDATE CmpProfile cp SET cp.signingCertificateUuid = NULL WHERE cp.signingCertificateUuid = ?1")
    void clearSigningCertificateReference(UUID signingCertificateUuid);

    @Modifying
    @Query("UPDATE CmpProfile cp SET cp.signingCertificateUuid = NULL WHERE cp.signingCertificateUuid IN ?1")
    void clearSigningCertificateReferenceIn(List<UUID> signingCertificateUuids);
}
