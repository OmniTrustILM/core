package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.certificate.*;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.*;
import com.otilm.api.model.core.location.LocationDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;

public interface CertificateExternalService {

    CertificateResponseDto listCertificates(SecurityFilter filter, CertificateSearchRequestDto request);

    CertificateDetailDto getCertificate(SecuredUUID uuid) throws NotFoundException, CertificateException, IOException;

    void deleteCertificate(SecuredUUID uuid) throws NotFoundException;

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

    FingerprintDto uploadAsync(UploadCertificateRequestDto request) throws CertificateException, AlreadyExistException;

    UuidDto uploadSync(UploadCertificateRequestDto request) throws CertificateException, AlreadyExistException;

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
     * Initiates the compliance check for the certificates in the request
     *
     * @param request List of uuids of the certificate
     */
    void checkCompliance(List<SecuredUUID> uuids) throws NotFoundException;

    /**
     * Update the Certificate Objects contents
     *
     * @param uuid    UUID of the certificate
     * @param request Request for the certificate objects update
     */
    void updateCertificateObjects(SecuredUUID uuid, CertificateUpdateObjectsDto request) throws NotFoundException, CertificateOperationException, AttributeException;

    /**
     * Method to update the Objects of multiple certificates
     *
     * @param request Request to update multiple objects
     */
    void bulkUpdateCertificatesObjects(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException, NotSupportedException;

    /**
     * Get the list of attributes to generate the CSR
     *
     * @return List of attributes to generate the CSR in core
     */
    List<BaseAttribute> getCsrGenerationAttributes();

    /**
     * Get the list of the certificate contents for the provided certificate UUIDs
     *
     * @param uuids UUIDs of the certificate
     * @return List of certificate contents
     */
    List<CertificateContentDto> getCertificateContent(List<UUID> uuids);

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
     * @param uuid            UUID of the subject certificate.
     * @param certificateUuid UUID of the certificate
     */
    void removeCertificateAssociation(UUID uuid, UUID certificateUuid) throws NotFoundException;

}
