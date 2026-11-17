package com.otilm.core.dao.repository;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * Queries every certificate type shares. They are written for the entity type of the repository that inherits them, so
 * {@link CertificateRepository} reads certificates of every type and a repository of one type reads only its own.
 *
 * <p>
 * Keep a query here derived, or name its entity with {@code #{#entityName}}: a query that spells out
 * {@code Certificate} would return every type from a subtype repository as well.
 */
@NoRepositoryBean
public interface CertificateBaseRepository<T extends Certificate> extends ComplianceSubjectRepository<T> {

    @EntityGraph(attributePaths = {"certificateContent"})
    Optional<T> findByUuid(UUID uuid);

    /**
     * Loads the certificate with its RA profile fetched eagerly, for callers that run without an ambient transaction
     * and would otherwise hit the lazy association detached.
     */
    @EntityGraph(attributePaths = "raProfile")
    Optional<T> findWithRaProfileByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"certificateContent", "raProfile"})
    List<T> findAllWithAssociationsByUuidIn(List<UUID> uuids);

    T findFirstByUuidIn(List<UUID> uuids);

    @EntityGraph(attributePaths = {
            "certificateContent",
            "key",
            "key.items",
            "groups",
            "owner",
            "altKey",
            "altKey.items",
            "raProfile"})
    Optional<T> findWithAssociationsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {
            "certificateContent",
            "key",
            "key.items",
            "groups",
            "owner",
            "altKey",
            "altKey.items",
            "raProfile",
            "raProfile.authorityInstanceReference",
            "raProfile.authorityInstanceReference.connectorInterface",
            "raProfile.authorityInstanceReference.connector"})
    Optional<T> findWithAuthorityAssociationsByUuid(UUID uuid);

    /**
     * Polling-listener finder. The listener runs outside any transaction (deliberate — no tx held across the HTTP call
     * to the connector), so every association the listener touches must be eagerly loaded here to avoid
     * {@link org.hibernate.LazyInitializationException}.
     */
    @EntityGraph(attributePaths = {
            "certificateContent",
            "raProfile",
            "raProfile.authorityInstanceReference",
            "raProfile.authorityInstanceReference.connectorInterface",
            "raProfile.authorityInstanceReference.connector"})
    Optional<T> findForPollingByUuid(UUID uuid);

    /**
     * Pessimistic-write variant of {@link #findWithAssociationsByUuid} for the operator-driven pending-state endpoints
     * and for {@code issuePlainCertificateAction}. Issues {@code SELECT ... FOR UPDATE} on the certificate row. Must be
     * called inside an active transaction, otherwise the lock is released immediately on query completion.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {
            "certificateContent",
            "key",
            "key.items",
            "groups",
            "owner",
            "altKey",
            "altKey.items",
            "raProfile",
            "raProfile.authorityInstanceReference",
            "raProfile.authorityInstanceReference.connectorInterface",
            "raProfile.authorityInstanceReference.connector"})
    Optional<T> findAndLockWithAssociationsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {
            "certificateContent",
            "key",
            "key.items",
            "groups",
            "owner",
            "altKey",
            "altKey.items",
            "raProfile"})
    List<T> findWithAssociationsByUuidInOrderByCreatedDesc(List<UUID> uuids);

    @EntityGraph(attributePaths = {"key", "key.items"})
    Optional<T> findForSigningByUuid(UUID uuid);

    Optional<T> findBySerialNumberIgnoreCase(String serialNumber);

    Optional<T> findByFingerprint(String fingerprint);

    List<T> findByPublicKeyFingerprint(String publicKeyFingerprint);

    boolean existsByCertificateRequestUuid(UUID certificateRequestUuid);

    List<T> findByRaProfile(RaProfile raProfile);

    @EntityGraph(attributePaths = {"certificateContent", "certificateRequestEntity"})
    List<T> findByUuidInAndArchivedFalse(List<UUID> uuids);

    @EntityGraph(attributePaths = {"certificateContent"})
    List<T> findByUuidInAndCertificateContentIdNotNullAndArchivedFalse(List<UUID> uuids);

    @EntityGraph(attributePaths = {"certificateContent"})
    List<T> findByRaProfileUuidAndCertificateContentIdNotNullAndArchivedFalse(UUID raProfileUuid);

    /**
     * Whether a certificate for this content is already committed. Discovery post-processing uses it to tell a group
     * that never ran from one whose import committed but whose result never reached the orchestrator — the two need
     * opposite records, and only the database can distinguish them.
     */
    boolean existsByCertificateContentId(Long certificateContentId);

    List<T> findByKeyUuid(UUID keyUuid);

    List<T> findByAltKeyUuid(UUID altKeyUuid);

    Optional<T> findByUserUuid(UUID userUuid);

    List<T> findByRaProfileAndComplianceStatusIsNotNullAndArchivedIsFalse(RaProfile raProfile);

    @EntityGraph(attributePaths = {"certificateContent", "raProfile"})
    List<T> findByValidationStatusAndCertificateContentDiscoveryCertificatesDiscoveryUuid(
            CertificateValidationStatus validationStatus, UUID discoveryUuid);

    @EntityGraph(attributePaths = {"certificateContent", "raProfile"})
    List<T> findByValidationStatusAndLocationsLocationUuid(CertificateValidationStatus validationStatus,
            UUID locationUuid);
}
