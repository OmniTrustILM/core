package com.otilm.core.dao.repository.signing;

import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface SigningProfileVersionRepository extends JpaRepository<SigningProfileVersion, UUID> {

    @EntityGraph(attributePaths = {
            "certificate",
            "certificate.certificateContent",
            "certificate.key",
            "certificate.key.items",})
    Optional<SigningProfileVersion> findWithAssociationsBySigningProfileUuidAndVersion(UUID signingProfileUuid,
            int version);

    Optional<SigningProfileVersion> findBySigningProfileUuidAndVersion(UUID signingProfileUuid, int version);

    @Modifying
    @Query("DELETE FROM SigningProfileVersion v WHERE v.signingProfileUuid = :signingProfileUuid")
    void deleteAllBySigningProfileUuid(UUID signingProfileUuid);

    @Query("SELECT DISTINCT v.signingProfile.name FROM SigningProfileVersion v WHERE v.tokenProfileUuid = :tokenProfileUuid ORDER BY v.signingProfile.name")
    List<String> findDistinctSigningProfileNamesByTokenProfileUuid(UUID tokenProfileUuid);

    @Query("SELECT DISTINCT v.signingProfile.name FROM SigningProfileVersion v WHERE v.tokenProfileUuid = :tokenProfileUuid AND v.version = v.signingProfile.latestVersion ORDER BY v.signingProfile.name")
    List<String> findSigningProfileNamesUsingTokenProfileInLatestVersion(UUID tokenProfileUuid);

    @Query("SELECT DISTINCT v.signingProfile.name FROM SigningProfileVersion v WHERE v.timestampSourceProfileUuid = :timestampSourceProfileUuid ORDER BY v.signingProfile.name")
    List<String> findSigningProfileNamesUsingTimestampSourceProfile(UUID timestampSourceProfileUuid);

    @Query("SELECT DISTINCT v.signingProfile.name FROM SigningProfileVersion v WHERE v.timestampSourceProfileUuid = :timestampSourceProfileUuid AND v.version = v.signingProfile.latestVersion ORDER BY v.signingProfile.name")
    List<String> findSigningProfileNamesUsingTimestampSourceProfileInLatestVersion(UUID timestampSourceProfileUuid);

    @Query("SELECT v FROM SigningProfileVersion v WHERE v.signingProfileUuid = :signingProfileUuid AND v.version = v.signingProfile.latestVersion")
    Optional<SigningProfileVersion> findLatestByProfileUuid(UUID signingProfileUuid);
}
