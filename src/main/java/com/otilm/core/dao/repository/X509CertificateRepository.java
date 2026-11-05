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

    List<X509CertificateEntity> findByPublicKeyFingerprintOrAltKeyFingerprint(String publicKeyFingerprint,
            String altKeyFingerprint);

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
