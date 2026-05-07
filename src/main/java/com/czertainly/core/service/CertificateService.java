package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.*;
import com.czertainly.api.model.client.dashboard.StatisticsDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.model.auth.CertificateProtocolInfo;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface CertificateService extends ResourceExtensionService  {

    CertificateResponseDto listCertificates(SecurityFilter filter, CertificateSearchRequestDto request);

    CertificateDetailDto getCertificate(SecuredUUID uuid) throws NotFoundException, CertificateException, IOException;

    Certificate getCertificateEntity(SecuredUUID uuid) throws NotFoundException;

    Certificate getCertificateEntityByContent(String content);

    Certificate getCertificateEntityByFingerprint(String fingerprint) throws NotFoundException;

    Certificate getCertificateEntityByIssuerDnNormalizedAndSerialNumber(String issuerDn, String serialNumber) throws NotFoundException;

    Optional<Certificate> findCertificateEntityByUserUuid(UUID userUuid);

    boolean checkCertificateExistsByFingerprint(String fingerprint);

    void deleteCertificate(SecuredUUID uuid) throws NotFoundException;

    Certificate createCertificateEntity(X509Certificate certificate);

    CertificateChainResponseDto getCertificateChain(SecuredUUID uuid, boolean withEndCertificate) throws NotFoundException;

    CertificateChainDownloadResponseDto downloadCertificateChain(SecuredUUID uuid, CertificateFormat certificateFormat, boolean withEndCertificate, CertificateFormatEncoding encoding) throws NotFoundException, CertificateException;

    CertificateDownloadResponseDto downloadCertificate(UUID uuid, CertificateFormat certificateFormat, CertificateFormatEncoding encoding) throws CertificateException, NotFoundException, IOException;

    /**
     * Function to get the validation result of the certificate
     *
     * @param uuid UUID of the certificate
     * @return Certificate Validation result
     * @throws NotFoundException
     */
    CertificateValidationResultDto getCertificateValidationResult(SecuredUUID uuid) throws NotFoundException, CertificateException;

    void validate(Certificate certificate);

    /**
     * Creates the Certificate entity
     *
     * @param certificateData Base64-encoded data of the certificate
     * @param certificateType Type of the certificate
     * @return Certificate entity
     */
    Certificate createCertificate(String certificateData, CertificateType certificateType) throws com.czertainly.api.exception.CertificateException;

    Certificate checkCreateCertificate(String certificate) throws AlreadyExistException, CertificateException, NoSuchAlgorithmException;

    CertificateContent checkAddCertificateContent(String fingerprint, String content);

    CertificateDetailDto upload(UploadCertificateRequestDto request, boolean ignoreCustomAttributes) throws AlreadyExistException, CertificateException, NoSuchAlgorithmException, NotFoundException, AttributeException;

    Certificate createCertificateAtomic(String certificate, boolean assignOwner) throws CertificateException, NoSuchAlgorithmException, NotFoundException;

    // TODO AUTH - unable to check access based on certificate serial number. Make private? Special permission? Call opa in method?
    void revokeCertificate(String serialNumber);

    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();

    void bulkDeleteCertificate(SecurityFilter filter, RemoveCertificateDto request) throws NotFoundException, NotSupportedException;

    /**
     * List all locations associated with the certificate
     *
     * @param certificateUuid
     * @return List of locations
     * @throws NotFoundException
     */
    List<LocationDto> listLocations(SecuredUUID certificateUuid) throws NotFoundException;

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
     * Initiates the compliance check for the certificates in the request
     *
     * @param request List of uuids of the certificate
     */
    void checkCompliance(CertificateComplianceCheckDto request) throws NotFoundException;

    /**
     * Update the Certificate Entity
     *
     * @param certificate Certificate entity to be updated
     */
    void updateCertificateEntity(Certificate certificate);

    /**
     * Update the Certificate Objects contents
     *
     * @param uuid    UUID of the certificate
     * @param request Request for the certificate objects update
     */
    void  updateCertificateObjects(SecuredUUID uuid, CertificateUpdateObjectsDto request) throws NotFoundException, CertificateOperationException, AttributeException;


    /**
     * Method to switch RA profile of a Certificate
     * @param uuid          UUID of the certificate
     * @param raProfileUuid UUID of the RA profile to switch to
     */
    void switchRaProfile(SecuredUUID uuid, SecuredUUID raProfileUuid) throws NotFoundException, CertificateOperationException, AttributeException;

    /**
     * Method to change Certificate Group for a Certificate
     * @param uuid      UUID of the certificate
     * @param groupUuids set of UUIDs of the certificate groups
     */
    void updateCertificateGroups(SecuredUUID uuid, Set<UUID> groupUuids) throws NotFoundException;


    /**
     * Method to change Owner for a Certificate
     * @param uuid        UUID of the certificate
     * @param ownerUuid   UUID of the certificate owner
     */
    void updateOwner(SecuredUUID uuid, String ownerUuid) throws NotFoundException;



        /**
         * Method to update the Objects of multiple certificates
         *
         * @param request Request to update multiple objects
         */
    void bulkUpdateCertificatesObjects(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException, NotSupportedException;

    /**
     * Function to update status of certificates by scheduled event
     *
     */
    int updateCertificatesStatusScheduled();

    /**
     * Update the user uuid of the certificate in the core database
     *
     * @param certificateUuid UUID of the certificate
     * @param userUuid        UUID of the User
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
     * Get the list of attributes to generate the CSR
     *
     * @return List of attributes to generate the CSR in core
     */
    List<BaseAttribute> getCsrGenerationAttributes();

    /**
     * Unassociate the given key from all the certificates.
     * @param keyUuid UUID of the key object or alternative key object to be unassociated
     */
    void clearKeyAssociations(UUID keyUuid);

    /**
     * Unassociate the given keys from all the certificates.
     * @param keyUuids list of UUID of the key objects or alternative key objects to be unassociated
     */
    void bulkClearKeyAssociations(List<UUID> keyUuids);

    /**
     * Function to update the certificate with the keys if known
     * @param keyUuid
     * @param publicKeyFingerprint
     * @throws NotFoundException
     */
    void updateCertificateKeys(UUID keyUuid, String publicKeyFingerprint);

    /**
     * Get the list of the certificate contents for the provided certificate UUIDs
     * @param uuids UUIDs of the certificate
     * @return List of certificate contents
     */
    List<CertificateContentDto> getCertificateContent(List<UUID> uuids);

    /**
     * Create certificate request entity and certificate in status New, store it in the database ready for issuing
     *
     * @param csr                        - PKCS10 certificate request to be added
     * @param csrFormat                  - format of the certificate request
     * @param signatureAttributes        signatureAttributes used to sign the CSR. If the CSR is uploaded from the User
     *                                   this parameter should be left empty
     * @param altSignatureAttributes     signatureAttributes used to sign the alternative private key, in case the CSR is for hybrid certificate
     * @param csrAttributes              Attributes used to create CSR
     * @param issueAttributes            Attributes used to issue certificate
     * @param keyUuid                    UUID of the key used to sign the CSR
     * @param altKeyUuid                 UUID of the alternative key used to sign the hybrid CSR
     * @param raProfileUuid              UUID of the RA profile to be used to issue certificate
     * @param predecessorCertificateUuid UUID of the predecessor certificate specified in case of renew/rekey operation
     *                                   return Certificate detail DTO
     */
    CertificateDetailDto submitCertificateRequest(String csr, CertificateRequestFormat csrFormat, List<RequestAttribute> signatureAttributes, List<RequestAttribute> altSignatureAttributes, List<RequestAttribute> csrAttributes, List<RequestAttribute> issueAttributes, UUID keyUuid,
                                                  UUID altKeyUuid, UUID raProfileUuid, UUID predecessorCertificateUuid, CertificateProtocolInfo protocolInfo) throws NoSuchAlgorithmException, ConnectorException, AttributeException, CertificateRequestException, NotFoundException;

    /**
     * Function to change the Certificate Entity from CSR to Certificate
     * @param uuid UUID of the entity to be transformed
     * @param certificateData Issued Certificate Data
     * @param meta Metadata of the certificate
     * @return Certificate detail DTO
     */
    CertificateDetailDto issueRequestedCertificate(UUID uuid, String certificateData, List<MetadataAttribute> meta) throws CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException, AttributeException;

    /**
     * List certificates eligible for CA certificate of SCEP requests
     * @param filter Security Filter
     * @param intuneEnabled flag to return certificates that are eligible for Intune integration
     * @return List of available CA certificates
     */
    List<CertificateDto> listScepCaCertificates(SecurityFilter filter, boolean intuneEnabled);

    /**
     * List certificates eligible for signing CMP responses
     * @param filter Security Filter
     * @return List of available signing certificates
     */
    List<CertificateDto> listCmpSigningCertificates(SecurityFilter filter);

    /**
     * Find certificates which are expiring and not renewed and trigger event handling these certificates
     */
    int handleExpiringCertificates();

    /**
     * Archives a single certificate by its UUID.
     *
     * @param uuid the UUID of the certificate to archive
     */
    void archiveCertificate(UUID uuid) throws NotFoundException;

    /**
     * Unarchives a single certificate by its UUID.
     *
     * @param uuid the UUID of the certificate to unarchive
     */
    void unarchiveCertificate(UUID uuid) throws NotFoundException;

    /**
     * Archives a list of certificates by their UUIDs.
     *
     * @param uuids the list of UUIDs of certificates to archive
     */
    void bulkArchiveCertificates(List<UUID> uuids);

    /**
     * Unarchives a list of certificates by their UUIDs.
     *
     * @param uuids the list of UUIDs of certificates to unarchive
     */
    void bulkUnarchiveCertificates(List<UUID> uuids);


    /***
     * Update Subject DN and Issuer DN in certificates when there is a change in code
     * @param oid of RDN to change
     * @param newCode to change
     * @param oldCode previous code to be changed
     */
    void updateCertificateDNs(String oid, String newCode, String oldCode);


    /**
     * Retrieves the relations for the given certificate.
     *
     * @param uuid UUID of the certificate whose relations should be retrieved.
     * @return {@link CertificateRelationsDto} containing related certificates.
     */
    CertificateRelationsDto getCertificateRelations(UUID uuid) throws NotFoundException;

    /**
     * Associates the given certificate with the subject certificate.
     *
     * @param uuid            UUID of the subject certificate.
     * @param certificateUuid UUID of the certificate to associate.
     */
    void associateCertificates(UUID uuid, UUID certificateUuid) throws NotFoundException;

    /**
     * Removes the association between the given certificates
     *
     * @param uuid                 UUID of the subject certificate.
     * @param certificateUuid UUID of the certificate
     */
    void removeCertificateAssociation(UUID uuid, UUID certificateUuid) throws NotFoundException;
}
