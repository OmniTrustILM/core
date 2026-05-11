package com.czertainly.core.dao.repository;

import com.czertainly.api.model.core.certificate.CertificateDto;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.custom.CustomCertificateRepository;
import org.springframework.data.domain.Pageable;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRepository extends SecurityFilterRepository<Certificate, UUID>, CustomCertificateRepository {

    @EntityGraph(attributePaths = {"certificateContent"})
    Optional<Certificate> findByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"certificateContent", "raProfile"})
    List<Certificate> findAllWithAssociationsByUuidIn(List<UUID> uuids);

    Certificate findFirstByUuidIn(List<UUID> uuids);

    @EntityGraph(attributePaths = {"certificateContent", "key", "key.items", "groups", "owner", "altKey", "altKey.items", "raProfile"})
    Optional<Certificate> findWithAssociationsByUuid(UUID uuid);

    /**
     * Pessimistic-write variant of {@link #findWithAssociationsByUuid} for the operator-driven
     * pending-state endpoints (manuallyIssueCertificate, manuallyConfirmRevoke,
     * cancelPendingCertificateOperation). Issues {@code SELECT ... FOR UPDATE} on the
     * certificate row so concurrent operator actions on the same pending certificate
     * serialize. Must be called inside an active transaction, otherwise the lock is
     * released immediately on query completion.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"certificateContent", "key", "key.items", "groups", "owner", "altKey", "altKey.items", "raProfile"})
    Optional<Certificate> findAndLockWithAssociationsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"certificateContent", "key", "key.items", "groups", "owner", "altKey", "altKey.items", "raProfile"})
    List<Certificate> findWithAssociationsByUuidInOrderByCreatedDesc(List<UUID> uuids);

    /** Fetches a single certificate with all associations required by {@link Certificate#mapToChainDto()}. */
    @EntityGraph("Certificate.chainAssociations")
    Optional<Certificate> findChainWithAssociationsByUuid(UUID uuid);

    /** Batch variant used when preloading a list of chain ancestors in one round-trip for {@link Certificate#mapToChainDto()}. */
    @EntityGraph("Certificate.chainAssociations")
    List<Certificate> findChainWithAssociationsByUuidIn(List<UUID> uuids);

    Optional<Certificate> findBySerialNumberIgnoreCase(String serialNumber);

    Certificate findByCertificateContent(CertificateContent certificateContent);

    Optional<Certificate> findByFingerprint(String fingerprint);

    List<Certificate> findByRaProfile(RaProfile raProfile);

    @EntityGraph(attributePaths = {"certificateContent", "certificateRequestEntity"})
    List<Certificate> findByUuidInAndArchivedFalse(List<UUID> uuids);

    @EntityGraph(attributePaths = {"certificateContent"})
    List<Certificate> findByUuidInAndCertificateContentIdNotNullAndArchivedFalse(List<UUID> uuids);

    @EntityGraph(attributePaths = {"certificateContent"})
    List<Certificate> findByRaProfileUuidAndCertificateContentIdNotNullAndArchivedFalse(UUID raProfileUuid);

    List<Certificate> findByKeyUuid(UUID keyUuid);

    List<Certificate> findByAltKeyUuid(UUID altKeyUuid);

    @Query("SELECT DISTINCT signatureAlgorithm FROM Certificate")
    List<String> findDistinctSignatureAlgorithm();

    @Query("SELECT DISTINCT altSignatureAlgorithm FROM Certificate")
    List<String> findDistinctAltSignatureAlgorithm();

    @Query("SELECT DISTINCT keySize FROM Certificate")
    List<Integer> findDistinctKeySize();

    @Query("SELECT DISTINCT altKeySize FROM Certificate")
    List<Integer> findDistinctAltKeySize();

    @Query("SELECT DISTINCT publicKeyAlgorithm FROM Certificate")
    List<String> findDistinctPublicKeyAlgorithm();

    @Query("SELECT DISTINCT altPublicKeyAlgorithm FROM Certificate")
    List<String> findDistinctAltPublicKeyAlgorithm();

    Optional<Certificate> findByUserUuid(UUID userUuid);

    List<Certificate> findByPublicKeyFingerprint(String fingerprint);

    @Query("""
             SELECT COUNT(*) FROM Certificate c LEFT JOIN c.raProfile rp
             WHERE c.certificateContentId IS NOT NULL AND c.validationStatus NOT IN :skipStatuses AND c.archived = false
             AND ((rp.validationEnabled is NULL AND :platformEnabled = true) OR (rp.validationEnabled = true))
            """)
    Long countCertificatesToCheckStatus(@Param("skipStatuses") List<CertificateValidationStatus> skipStatuses, @Param("platformEnabled") boolean platformEnabled);


    // Select certificates which have content, and they are not revoked, expired (since these statuses cannot change) or archived
    // Select certificates according to platform settings, this applies to certificates which either do not have RA Profile assigned or certificates which have RA Profile
    // assigned, validation for that RA Profile is null
    // Select certificates which have validation frequency set in RA Profile
    @Query("""
            SELECT c.uuid FROM Certificate c LEFT JOIN c.raProfile rp
                WHERE c.certificateContentId IS NOT NULL AND c.validationStatus NOT IN :skipStatuses AND c.archived = false
                    AND
                    (
                ((rp.validationEnabled is NULL AND :platformEnabled = true) AND (c.statusValidationTimestamp IS NULL OR c.statusValidationTimestamp <= :statusValidityEndTimestamp))
                    OR
                ((rp.validationEnabled = true) AND (c.statusValidationTimestamp IS NULL OR c.statusValidationTimestamp <= CURRENT_DATE - rp.validationFrequency DAY))
                    ) ORDER BY c.statusValidationTimestamp ASC NULLS FIRST
            """
    )
    List<UUID> findCertificatesToCheckStatus(@Param("statusValidityEndTimestamp") OffsetDateTime statusValidityEndTimestamp,
                                             @Param("skipStatuses") List<CertificateValidationStatus> skipStatuses,
                                             @Param("platformEnabled") boolean platformEnabled,
                                             Pageable pageable);

    List<Certificate> findByRaProfileAndComplianceStatusIsNotNullAndArchivedIsFalse(RaProfile raProfile);

    Optional<Certificate> findBySubjectDnNormalizedAndSerialNumber(String subjectDnNormalized, String serialNumber);

    Optional<Certificate> findByIssuerDnNormalizedAndSerialNumber(String issuerDnNormalized, String serialNumber);

    @EntityGraph(attributePaths = {"certificateContent"})
    List<Certificate> findBySubjectDnNormalized(String issuerDnNormalized);

    @EntityGraph(attributePaths = {"certificateContent", "raProfile"})
    List<Certificate> findByValidationStatusAndCertificateContentDiscoveryCertificatesDiscoveryUuid(CertificateValidationStatus validationStatus, UUID discoveryUuid);

    @EntityGraph(attributePaths = {"certificateContent", "raProfile"})
    List<Certificate> findByValidationStatusAndLocationsLocationUuid(CertificateValidationStatus validationStatus, UUID locationUuid);

    @Modifying
    @Query("UPDATE Certificate c SET c.keyUuid = ?1 WHERE c.uuid IN ?2")
    void setKeyUuid(UUID keyUuid, List<UUID> uuids);

    @Modifying
    @Query("UPDATE Certificate c SET c.keyUuid = NULL WHERE c.keyUuid = ?1")
    void clearKeyAssociations(UUID keyUuid);

    @Modifying
    @Query("UPDATE Certificate c SET c.keyUuid = NULL WHERE c.keyUuid IN ?1")
    void clearKeyAssociationsIn(List<UUID> keyUuids);

    @Modifying
    @Query("UPDATE Certificate c SET c.altKeyUuid = NULL WHERE c.altKeyUuid = ?1")
    void clearAltKeyAssociations(UUID altKeyUuid);

    @Modifying
    @Query("UPDATE Certificate c SET c.altKeyUuid = NULL WHERE c.altKeyUuid IN ?1")
    void clearAltKeyAssociationsIn(List<UUID> altKeyUuids);

    @Modifying
    @Query("UPDATE Certificate c SET c.archived = ?1 WHERE c.uuid IN ?2")
    void archiveCertificates(boolean archive, List<UUID> uuids);

    @Modifying
    @Query("UPDATE Certificate c SET c.altKeyUuid = ?1, c.hybridCertificate = true WHERE c.uuid IN ?2")
    void setAltKeyUuidAndHybridCertificate(UUID keyUuid, List<UUID> uuids);

    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}certificate (
            uuid, i_author, i_cre, i_upd, ra_profile_uuid,certificate_content_id,
            certificate_request_uuid,issuer_certificate_uuid,certificate_type,
            state,validation_status,certificate_validation_result,status_validation_timestamp,
            compliance_status,compliance_result,common_name,not_after,not_before,
            extended_key_usage,fingerprint,issuer_common_name,issuer_dn,issuer_dn_normalized,
            issuer_serial_number,key_size,key_usage,key_uuid,public_key_algorithm,
            public_key_fingerprint,serial_number,signature_algorithm,subject_alternative_names,
            subject_dn,subject_dn_normalized,subject_type,trusted_ca,user_uuid,hybrid_certificate,alt_signature_algorithm,archived,alt_key_fingerprint)
            VALUES (
            :#{#cert.uuid}, :#{#cert.author}, :#{#cert.created}, :#{#cert.updated}, :#{#cert.raProfileUuid}, :#{#cert.certificateContentId},
            :#{#cert.certificateRequestUuid}, :#{#cert.issuerCertificateUuid}, :#{#cert.certificateType.name()},
            :#{#cert.state.name()}, :#{#cert.validationStatus.name()}, :#{#cert.certificateValidationResult}, :#{#cert.statusValidationTimestamp},
            :#{#cert.complianceStatus.name()}, :#{#cert.complianceResult}, :#{#cert.commonName}, :#{#cert.notAfter}, :#{#cert.notBefore},
            :#{#cert.extendedKeyUsage}, :#{#cert.fingerprint}, :#{#cert.issuerCommonName}, :#{#cert.issuerDn}, :#{#cert.issuerDnNormalized},
            :#{#cert.issuerSerialNumber}, :#{#cert.keySize}, :#{#cert.keyUsageBitMask}, :#{#cert.keyUuid}, :#{#cert.publicKeyAlgorithm},
            :#{#cert.publicKeyFingerprint}, :#{#cert.serialNumber}, :#{#cert.signatureAlgorithm}, :#{#cert.subjectAlternativeNames},
            :#{#cert.subjectDn}, :#{#cert.subjectDnNormalized}, :#{#cert.subjectType.name()}, :#{#cert.trustedCa}, :#{#cert.userUuid},
            :#{#cert.hybridCertificate}, :#{#cert.altSignatureAlgorithm}, :#{#cert.archived}, :#{#cert.altKeyFingerprint}
            )
            ON CONFLICT (fingerprint)
            DO NOTHING
            """, nativeQuery = true)
    Integer insertWithFingerprintConflictResolve(@Param("cert") Certificate certificate);

    @Query("""
             SELECT c.uuid
                FROM Certificate c
                LEFT JOIN CertificateRelation cr
                    ON cr.id.predecessorCertificateUuid = c.uuid
                WHERE c.validationStatus = ?#{T(com.czertainly.api.model.core.certificate.CertificateValidationStatus).EXPIRING}
                  AND c.archived = false
                  AND (
                      cr.id.predecessorCertificateUuid IS NULL
                              OR NOT EXISTS (
                                    SELECT 1
                                    FROM CertificateRelation scr
                                    JOIN Certificate sc ON sc.uuid = scr.id.successorCertificateUuid
                                    WHERE scr.id.predecessorCertificateUuid = c.uuid
                                        AND sc.state = ?#{T(com.czertainly.api.model.core.certificate.CertificateState).ISSUED}
                              )
                  )
            """)
    List<UUID> findExpiringCertificatesWithoutRenewal();

    @Query(
            value = """
                        UPDATE {h-schema}certificate
                        SET subject_dn = REGEXP_REPLACE(
                                 subject_dn,
                                 '(^|, )(' || :oldCode || ')(=)',
                                 '\\1' || :newCode || '\\3',
                                 'g'
                             )
                        WHERE subject_dn_normalized ~ ('(^|, )' || :oid || '=');
                    """,
            nativeQuery = true
    )
    @Modifying
    void updateCertificateSubjectDN(@Param("oid") String oid,
                                    @Param("newCode") String newCode,
                                    @Param("oldCode") String oldCode);

    /**
     * Fetches the UUIDs of an entire certificate ancestor chain in a single recursive CTE query, starting from the
     * certificate identified by {@code startUuid}.
     *
     * <p>The returned list is ordered by traversal depth ascending, so index 0 is always the start certificate itself,
     * and the last element is the topmost ancestor found in the inventory.</p>
     *
     * @param startUuid the UUID of the certificate whose chain is requested
     * @param maxDepth  maximum number of hops to follow (safety cap against circular references)
     * @return ordered list of UUID strings (depth 0 = start cert, depth N = root)
     */
    // NOTE: PostgreSQL 14+ supports a cleaner native cycle-detection syntax via the CYCLE clause.
    @Query(value = """
            WITH RECURSIVE chain AS (
                SELECT uuid, issuer_certificate_uuid, 0 AS depth, ARRAY[uuid] AS path
                FROM {h-schema}certificate
                WHERE uuid = :startUuid

                UNION ALL

                SELECT c.uuid, c.issuer_certificate_uuid, chain.depth + 1, chain.path || c.uuid
                FROM {h-schema}certificate c
                INNER JOIN chain ON chain.issuer_certificate_uuid = c.uuid
                WHERE chain.depth < :maxDepth
                  AND NOT (c.uuid = ANY(chain.path))
            )
            SELECT uuid::text FROM chain ORDER BY depth ASC
            """, nativeQuery = true)
    List<String> findCertificateChainUuids(@Param("startUuid") UUID startUuid, @Param("maxDepth") int maxDepth);

    @Query(
            value = """
                        UPDATE {h-schema}certificate
                        SET issuer_dn = REGEXP_REPLACE(
                                issuer_dn,
                                '(^|, )(' || :oldCode || ')(=)',
                                '\\1' || :newCode || '\\3',
                                'g'
                            )
                        WHERE issuer_dn_normalized ~ ('(^|, )' || :oid || '=');
                    """,
            nativeQuery = true
    )
    @Modifying
    void updateCertificateIssuerDN(@Param("oid") String oid,
                                   @Param("newCode") String newCode,
                                   @Param("oldCode") String oldCode);

    /** Populates almost all of the {@link CertificateDto} properties.
     *
     * <p>Groups need to be retrieved separately and set to the DTO.</p>
     */
    @Query("""
            SELECT new com.czertainly.api.model.core.certificate.CertificateDto(
                c.uuid, c.commonName, c.serialNumber, c.issuerCommonName, c.issuerDn, c.subjectDn, c.notBefore, c.notAfter,
                c.publicKeyAlgorithm, c.altPublicKeyAlgorithm, c.signatureAlgorithm, c.altSignatureAlgorithm, c.hybridCertificate,
                c.keySize, c.altKeySize, c.state, c.validationStatus,
                ra.uuid, ra.name, ra.enabled, ra.authorityInstanceReferenceUuid,
                c.fingerprint, oa.ownerUsername, oa.ownerUuid, c.certificateType, c.issuerSerialNumber, c.complianceStatus,
                c.issuerCertificateUuid,
                (CASE WHEN c.keyUuid IS NOT NULL AND EXISTS
                    (SELECT 1 FROM CryptographicKeyItem i WHERE i.keyUuid = c.keyUuid
                        AND i.type = ?#{T(com.czertainly.api.model.common.enums.cryptography.KeyType).PRIVATE_KEY}
                        AND i.state = ?#{T(com.czertainly.api.model.core.cryptography.key.KeyState).ACTIVE}
                    )
                    THEN true ELSE false END
                ),
                c.trustedCa, c.archived
            )
            FROM Certificate c
            LEFT JOIN OwnerAssociation oa ON oa.objectUuid = c.uuid
            LEFT JOIN RaProfile ra ON ra.uuid = c.raProfileUuid
            WHERE c.uuid IN ?1
            ORDER BY c.created DESC
            """)
    List<CertificateDto> findCertificateDtosByUuidsIn(List<UUID> uuids);
}
