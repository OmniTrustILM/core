package com.otilm.core.dao.repository.signing;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.signing.CertificateHold;
import java.util.Collection;
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

    /**
     * Names the profiles of the given workflows that sign, or once signed, with the key, through whichever certificate
     * carries it. Every stored version counts, superseded ones too: a signature stays valid after its profile has moved
     * to another key.
     */
    @Query("""
            SELECT DISTINCT v.signingProfile.name FROM SigningProfileVersion v
            WHERE v.certificate.keyUuid = :keyUuid
              AND v.workflowType IN :workflowTypes
            ORDER BY v.signingProfile.name
            """)
    List<String> findProfileNamesBySigningKeyAndWorkflowIn(UUID keyUuid, Collection<SigningWorkflowType> workflowTypes);

    /**
     * The profiles whose stored versions hold one of the certificates, superseded versions too: they keep their
     * certificate for the key's signing history. A profile comes back at most twice per certificate, once for its
     * current version and once for its superseded ones, however many versions it has.
     */
    @Query("""
            SELECT DISTINCT new com.otilm.core.signing.CertificateHold(
                v.certificateUuid, p.name, CASE WHEN v.version = p.latestVersion THEN true ELSE false END)
            FROM SigningProfileVersion v JOIN v.signingProfile p
            WHERE v.certificateUuid IN :certificateUuids
            """)
    List<CertificateHold> findCertificateHolds(Collection<UUID> certificateUuids);
}
