package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.X509CertificateEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Repository of X.509 certificates. It inherits the queries every certificate type shares, limited to X.509
 * certificates, and adds the ones that read what only X.509 has: the DNs, the issuer serial and the alternative key.
 */
@Repository
public interface X509CertificateRepository extends CertificateBaseRepository<X509CertificateEntity> {

    @EntityGraph(attributePaths = {"certificateContent"})
    List<X509CertificateEntity> findBySubjectDnNormalized(String subjectDnNormalized);

    Optional<X509CertificateEntity> findBySubjectDnNormalizedAndSerialNumber(String subjectDnNormalized,
            String serialNumber);

    Optional<X509CertificateEntity> findByIssuerDnNormalizedAndSerialNumber(String issuerDnNormalized,
            String serialNumber);

    List<X509CertificateEntity> findByAltKeyFingerprint(String altKeyFingerprint);

    @Modifying
    @Query("UPDATE X509CertificateEntity c SET c.altKeyUuid = ?1, c.hybridCertificate = true WHERE c.uuid IN ?2")
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
            subject_dn,subject_dn_normalized,subject_type,trusted_ca,user_uuid,hybrid_certificate,alt_signature_algorithm,archived,alt_key_fingerprint,
            qc_compliance,extended_key_usage_critical,qc_sscd,qc_type,qc_cc_legislation)
            VALUES (
            :#{#cert.uuid}, :#{#cert.author}, :#{#cert.created}, :#{#cert.updated}, :#{#cert.raProfileUuid}, :#{#cert.certificateContentId},
            :#{#cert.certificateRequestUuid}, :#{#cert.issuerCertificateUuid}, :#{#cert.certificateType.name()},
            :#{#cert.state.name()}, :#{#cert.validationStatus.name()}, :#{#cert.certificateValidationResult}, :#{#cert.statusValidationTimestamp},
            :#{#cert.complianceStatus.name()}, :#{#cert.complianceResult}, :#{#cert.commonName}, :#{#cert.notAfter}, :#{#cert.notBefore},
            :#{#cert.extendedKeyUsage}, :#{#cert.fingerprint}, :#{#cert.issuerCommonName}, :#{#cert.issuerDn}, :#{#cert.issuerDnNormalized},
            :#{#cert.issuerSerialNumber}, :#{#cert.keySize}, :#{#cert.keyUsageBitMask}, :#{#cert.keyUuid}, :#{#cert.publicKeyAlgorithm},
            :#{#cert.publicKeyFingerprint}, :#{#cert.serialNumber}, :#{#cert.signatureAlgorithm}, :#{#cert.subjectAlternativeNames},
            :#{#cert.subjectDn}, :#{#cert.subjectDnNormalized}, :#{#cert.subjectType.name()}, :#{#cert.trustedCa}, :#{#cert.userUuid},
            :#{#cert.hybridCertificate}, :#{#cert.altSignatureAlgorithm}, :#{#cert.archived}, :#{#cert.altKeyFingerprint},
            :#{#cert.qcCompliance}, :#{#cert.extendedKeyUsageCritical}, :#{#cert.qcSscd}, :#{#cert.qcType}, :#{#cert.qcCcLegislation}
            )
            ON CONFLICT (fingerprint)
            DO NOTHING
            """,
            nativeQuery = true)
    Integer insertWithFingerprintConflictResolve(@Param("cert") X509CertificateEntity certificate);

    /**
     * The pre-registrations a protocol enrolment presenting the given normalized subject can complete under the RA
     * profile: REGISTERED placeholders whose registration authorization is ACTIVE, prefiltered by the stored normalized
     * subject so the identity match receives only same-subject candidates. Registrations without a challenge have no
     * authorization row and are excluded — they cannot authenticate an enrolment.
     *
     * <p>
     * Rows whose normalized subject is NULL are always included and left for the caller's identity match to resolve: a
     * placeholder written by an old instance during a rolling upgrade — after the one-shot backfill has already run —
     * carries no normalized subject, and an equality-only prefilter would make it permanently unmatchable. NULL rows
     * are only ever produced transiently by such writers, so the prefilter's narrowing still holds in steady state.
     */
    @Query("""
            SELECT c FROM X509CertificateEntity c
                WHERE c.raProfileUuid = :raProfileUuid
                    AND (c.subjectDnNormalized = :subjectDnNormalized OR c.subjectDnNormalized IS NULL)
                    AND c.state = ?#{T(com.otilm.api.model.core.certificate.CertificateState).REGISTERED}
                    AND c.archived = false
                    AND EXISTS (SELECT 1 FROM CertificateRegistrationAuthorization a
                        WHERE a.certificateUuid = c.uuid
                            AND a.state = ?#{T(com.otilm.core.dao.entity.RegistrationState).ACTIVE})
            """)
    List<X509CertificateEntity> findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(
            @Param("raProfileUuid") UUID raProfileUuid, @Param("subjectDnNormalized") String subjectDnNormalized);

    @Query("SELECT DISTINCT c.altSignatureAlgorithm FROM X509CertificateEntity c")
    List<String> findDistinctAltSignatureAlgorithm();

    @Query("SELECT DISTINCT c.altKeySize FROM X509CertificateEntity c")
    List<Integer> findDistinctAltKeySize();

    @Query("SELECT DISTINCT c.altPublicKeyAlgorithm FROM X509CertificateEntity c")
    List<String> findDistinctAltPublicKeyAlgorithm();

    /**
     * Sets {@code issuer_serial_number} and {@code issuer_certificate_uuid} on a single certificate row by UUID,
     * refreshing {@code i_upd} explicitly.
     */
    @Modifying
    @Query("UPDATE X509CertificateEntity c "
            + "SET c.issuerSerialNumber = :serial, c.issuerCertificateUuid = :issuerUuid, "
            + "    c.updated = CURRENT_TIMESTAMP " + "WHERE c.uuid = :uuid")
    void updateIssuerReference(@Param("uuid") UUID uuid, @Param("serial") String serial,
            @Param("issuerUuid") UUID issuerUuid);

    /**
     * Clears both {@code issuer_serial_number} and {@code issuer_certificate_uuid} on a single certificate row.
     */
    @Modifying
    @Query("UPDATE X509CertificateEntity c " + "SET c.issuerSerialNumber = NULL, c.issuerCertificateUuid = NULL, "
            + "    c.updated = CURRENT_TIMESTAMP " + "WHERE c.uuid = :uuid")
    void clearIssuerReference(@Param("uuid") UUID uuid);
}
