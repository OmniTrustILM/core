package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.events.handlers.discovery.DiscoveredCertificateImport;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface CertificateInternalService extends ResourceExtensionService {

    Certificate getCertificateEntity(SecuredUUID uuid) throws NotFoundException;

    Certificate getCertificateEntityByContent(String content);

    Certificate getCertificateEntityByFingerprint(String fingerprint) throws NotFoundException;

    Certificate getCertificateEntityByIssuerDnNormalizedAndSerialNumber(String issuerDn, String serialNumber)
            throws NotFoundException;

    Optional<Certificate> findCertificateEntityByUserUuid(UUID userUuid);

    boolean checkCertificateExistsByFingerprint(String fingerprint);

    Certificate createCertificateEntity(X509Certificate certificate);

    /**
     * Creates or adopts the certificate for a discovered content group, resolving a concurrent insert of the same
     * certificate rather than failing on it.
     *
     * <p>
     * Performs no authorization check of its own: discovery authorizes {@code (CERTIFICATE, CREATE)} once per run,
     * outside any transaction, because enforcement is a blocking OPA request. Any other caller must authorize for
     * itself.
     */
    DiscoveredCertificateImport createDiscoveredCertificateAtomic(X509Certificate certificate)
            throws NoSuchAlgorithmException, CertificateEncodingException, NotFoundException;

    /**
     * Creates a no-CSR placeholder certificate for a v3 authority registration: an identity-only record in state
     * REQUESTED, created before any CSR exists. A later CSR-driven issuance completes the certificate against this
     * placeholder.
     *
     * @param effectiveSubjectDn the subject DN to persist — the flat {@code subjectDn} for a flat request, or the DN
     * rendered from projected {@code csrAttributes} for a structured one (resolved by the caller so the placeholder
     * matches the register wire identity)
     * @param registrationContent the projected registration identity content; its subject alternative names are
     * persisted on the placeholder alongside the subject DN, so the platform record carries the full registered
     * identity (may be null)
     * @param sourceCertificate the existing certificate this registration succeeds, or null for a standalone
     * placeholder. When set, a PENDING relation to the source is written in the same transaction as the placeholder, so
     * completing the placeholder later resolves as the source's renewal or rekey
     */
    Certificate createRegistrationPlaceholder(RaProfile raProfile, String effectiveSubjectDn,
            X509RequestContent registrationContent, Certificate sourceCertificate) throws NotFoundException;

    /**
     * Associates the certificate with the protocol that obtained it, exactly as for a protocol-submitted request: the
     * protocol-association row is recorded and the protocol profile's certificate associations (owner, groups, custom
     * attributes) are applied — a profile-configured owner or group replaces one set earlier, including at registration
     * time.
     */
    void applyProtocolAssociations(UUID certificateUuid, CertificateProtocolInfo protocolInfo)
            throws NotFoundException, AttributeException;

    /**
     * Attaches an operator-supplied CSR to an existing certificate (a REGISTERED placeholder), preparing it for
     * issuance. The registration identity already on the row (subject DN / SAN) is preserved; the issued certificate's
     * identity is written from the CA response at issuance.
     */
    UUID addCertificateRequestToExisting(UUID certificateUuid, ClientCertificateIssueRequestDto issueRequest)
            throws CertificateRequestException, NoSuchAlgorithmException, NotFoundException;

    CertificateChainResponseDto getCertificateChain(SecuredUUID uuid, boolean withEndCertificate)
            throws NotFoundException;

    /**
     * Hot-path variant for digital signing. Best-effort (no AIA fetch, no DB writes), no authorization — must not be
     * called from REST controllers. Returns an empty list if UUID is unknown or cert has no stored content; the empty
     * list is cached under the key so a repeated miss does not hit the DB.
     *
     * @throws CertificateException if any chain entry cannot be parsed
     */
    List<X509Certificate> getCertificateChainForSigning(UUID certificateUuid, boolean withEndCertificate)
            throws CertificateException;

    /**
     * Hot-path accessor for digital signing. Returns an immutable snapshot of the certificate's acceptability data and
     * structural key references, cached in {@link CacheConfig#SIGNING_CERTIFICATE_CACHE}.
     *
     * <p>
     * No authorization check — must not be called from REST controllers.
     *
     * @throws NotFoundException if no certificate exists for the UUID
     */
    SigningCertificate getSigningCertificate(UUID certificateUuid) throws NotFoundException;

    void validate(Certificate certificate);

    /**
     * Creates the Certificate entity
     *
     * @param certificateData Base64-encoded data of the certificate
     * @param certificateType Type of the certificate
     * @return Certificate entity
     */
    Certificate createCertificate(String certificateData, CertificateType certificateType)
            throws com.otilm.api.exception.CertificateException;

    Certificate checkCreateCertificate(String certificate)
            throws AlreadyExistException, CertificateException, NoSuchAlgorithmException;

    void uploadCertificateKey(PublicKey publicKey, Certificate certificate, byte[] altPublicKeyEncoded);

    CertificateContent checkAddCertificateContent(String fingerprint, String content);

    Certificate createCertificateAtomic(String certificate, boolean assignOwner)
            throws CertificateException, NoSuchAlgorithmException, NotFoundException;

    // TODO AUTH - unable to check access based on certificate serial number. Make private? Special permission? Call opa
    // in method?
    void revokeCertificate(String serialNumber);

    /**
     * List the available certificates that are associated with the RA Profile
     *
     * @param raProfile Ra Profile entity to search for the certificates
     * @return List of Certificates
     */
    List<Certificate> listCertificatesForRaProfile(RaProfile raProfile);

    /**
     * List the available certificates that are associated with the RA Profile
     *
     * @param raProfile Ra Profile entity to search for the certificates
     * @return List of Certificates
     */
    List<Certificate> listCertificatesForRaProfileAndNonNullComplianceStatus(RaProfile raProfile);

    /**
     * Update the Certificate Entity
     *
     * @param certificate Certificate entity to be updated
     */
    void updateCertificateEntity(Certificate certificate);

    /**
     * Method to switch RA profile of a Certificate
     *
     * @param uuid UUID of the certificate
     * @param raProfileUuid UUID of the RA profile to switch to
     * @param identifyAttributes identify-operation attribute values for the new RA profile's authority (schema from its
     * identify attribute listing); ignored when {@code raProfileUuid} is null (RA-profile removal — no identify runs).
     * May be null or empty when the operator supplied none.
     */
    void switchRaProfile(SecuredUUID uuid, SecuredUUID raProfileUuid, List<RequestAttribute> identifyAttributes)
            throws NotFoundException, CertificateOperationException, AttributeException;

    /**
     * Method to change Certificate Group for a Certificate
     *
     * @param uuid UUID of the certificate
     * @param groupUuids set of UUIDs of the certificate groups
     */
    void updateCertificateGroups(SecuredUUID uuid, Set<UUID> groupUuids) throws NotFoundException;

    /**
     * Method to change Owner for a Certificate
     *
     * @param uuid UUID of the certificate
     * @param ownerUuid UUID of the certificate owner
     */
    void updateOwner(SecuredUUID uuid, String ownerUuid) throws NotFoundException;

    /**
     * Function to update status of certificates by scheduled event
     *
     */
    int updateCertificatesStatusScheduled();

    /**
     * Update the user uuid of the certificate in the core database
     *
     * @param certificateUuid UUID of the certificate
     * @param userUuid UUID of the User
     * @throws NotFoundException
     */
    void updateCertificateUser(UUID certificateUuid, String userUuid) throws NotFoundException;

    /**
     * Remove the user uuid of the certificate in the core database
     *
     * @param userUuid UUID of the User
     */
    void removeCertificateUser(UUID userUuid);

    /**
     * Get the number of certificates per user for dashboard
     *
     * @return Number of certificates
     */
    Long statisticsCertificateCount(SecurityFilter filter, boolean includeArchived);

    /**
     * Add statistics information based on the permission with the logged in user
     *
     * @param dto Statistics DTO with predefined records
     * @param includeArchived include also archived certificates in statistics
     * @return Statistics DTO
     */
    StatisticsDto addCertificateStatistics(SecurityFilter filter, StatisticsDto dto, boolean includeArchived);

    /**
     * Method to check if the permission is available for the user to create certificate and submit certificate request
     */
    void checkCreatePermissions();

    /**
     * Method to check if the permission is available for the user to pre-register certificate
     */
    void checkRegisterPermissions();

    /**
     * Method to check if the permission is available for the user to issue certificate
     */
    void checkIssuePermissions();

    /**
     * Method to check if the permission is available for the user to renew certificate
     */
    void checkRenewPermissions();

    /**
     * Method to check if the permission is available for the user to revoke certificate
     */
    void checkRevokePermissions();

    /**
     * Unassociate the given key from all the certificates.
     *
     * @param keyUuid UUID of the key object or alternative key object to be unassociated
     */
    void clearKeyAssociations(UUID keyUuid);

    /**
     * Unassociate the given keys from all the certificates.
     *
     * @param keyUuids list of UUID of the key objects or alternative key objects to be unassociated
     */
    void bulkClearKeyAssociations(List<UUID> keyUuids);

    /**
     * Function to update the certificate with the keys if known
     *
     * @param keyUuid
     * @param publicKeyFingerprint
     * @throws NotFoundException
     */
    void updateCertificateKeys(UUID keyUuid, String publicKeyFingerprint);

    /**
     * Returns the stored certificate request with this content, the one {@link #submitCertificateRequest} would reuse.
     *
     * @param csr Base64-encoded certificate request, as passed to {@link #submitCertificateRequest}
     */
    Optional<CertificateRequestEntity> findCertificateRequestByContent(String csr) throws NoSuchAlgorithmException;

    /**
     * Create certificate request entity and certificate in status New, store it in the database ready for issuing
     * <p>
     * This method performs local persistence only. The caller must have merged and validated the issue attributes
     * against the authority connector beforehand (see
     * {@code ExtendedAttributeService#mergeAndValidateIssueAttributes}), both to enforce connector-side validation and
     * to register the attribute definitions this method writes content against. Callers do that outside their
     * persistence transaction, so the connector round-trip does not hold a database connection.
     *
     * @param csr - PKCS10 certificate request to be added
     * @param csrFormat - format of the certificate request
     * @param signatureAttributes signatureAttributes used to sign the CSR. If the CSR is uploaded from the User this
     * parameter should be left empty
     * @param altSignatureAttributes signatureAttributes used to sign the alternative private key, in case the CSR is
     * for hybrid certificate
     * @param csrAttributes Attributes used to create CSR
     * @param issueAttributes Attributes used to issue certificate
     * @param keyUuid UUID of the key used to sign the CSR
     * @param altKeyUuid UUID of the alternative key used to sign the hybrid CSR
     * @param raProfileUuid UUID of the RA profile to be used to issue certificate
     * @param predecessorCertificateUuid UUID of the predecessor certificate specified in case of renew/rekey operation
     * return Certificate detail DTO
     */
    CertificateDetailDto submitCertificateRequest(String csr, CertificateRequestFormat csrFormat,
            List<RequestAttribute> signatureAttributes, List<RequestAttribute> altSignatureAttributes,
            List<RequestAttribute> csrAttributes, List<RequestAttribute> issueAttributes, UUID keyUuid, UUID altKeyUuid,
            UUID raProfileUuid, UUID predecessorCertificateUuid, CertificateProtocolInfo protocolInfo)
            throws NoSuchAlgorithmException, ConnectorException, AttributeException, CertificateRequestException,
            NotFoundException;

    /**
     * Function to change the Certificate Entity from CSR to Certificate
     *
     * @param uuid UUID of the entity to be transformed
     * @param certificateData Issued Certificate Data
     * @param meta Metadata of the certificate
     * @return Certificate detail DTO
     */
    CertificateDetailDto issueRequestedCertificate(UUID uuid, String certificateData, List<MetadataAttribute> meta)
            throws CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException,
            AttributeException;

    /**
     * List certificates eligible for CA certificate of SCEP requests
     *
     * @param filter Security Filter
     * @param intuneEnabled flag to return certificates that are eligible for Intune integration
     * @return List of available CA certificates
     */
    List<CertificateDto> listScepCaCertificates(SecurityFilter filter, boolean intuneEnabled);

    /**
     * List certificates eligible for signing CMP responses
     *
     * @param filter Security Filter
     * @return List of available signing certificates
     */
    List<CertificateDto> listCmpSigningCertificates(SecurityFilter filter);

    /**
     * List certificates eligible for digital signing.
     *
     * @param filter security filter
     * @param signingWorkflowType digital signing workflow type
     * @param qualifiedTimestamp when {@code true} and workflow is TIMESTAMPING, restricts results to certificates that
     * satisfy ETSI EN 319 421 qualified timestamp requirements
     * @param certificatePurpose per-profile purpose constraints meaningful for the content- and raw-signing workflows
     * @return List of available certificates
     */
    List<CertificateDto> listDigitalSigningCertificates(SecurityFilter filter, SigningWorkflowType signingWorkflowType,
            boolean qualifiedTimestamp, CertificatePurposeRequirements certificatePurpose);

    /**
     * Find certificates which are expiring and not renewed and trigger event handling these certificates
     */
    int handleExpiringCertificates();

    /***
     * Update Subject DN and Issuer DN in certificates when there is a change in code
     *
     * @param oid of RDN to change
     * @param newCode to change
     * @param oldCode previous code to be changed
     */
    void updateCertificateDNs(String oid, String newCode, String oldCode);

}
