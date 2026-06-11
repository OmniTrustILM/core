package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRelationDto;
import com.otilm.api.model.client.compliance.SimplifiedComplianceProfileDto;
import com.otilm.api.model.client.raprofile.*;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.raprofile.RaProfileDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredList;

import java.util.List;
import java.util.Optional;

public interface RaProfileService extends ResourceExtensionService {

    List<RaProfileDto> listRaProfiles(SecurityFilter filter, Optional<Boolean> enabled);

    SecuredList<RaProfile> listRaProfilesAssociatedWithAcmeProfile(String acmeProfileUuid, SecurityFilter filter);

    RaProfileDto addRaProfile(SecuredParentUUID authorityUuid, AddRaProfileRequestDto dto) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException;

    RaProfileDto getRaProfile(SecuredUUID uuid) throws NotFoundException;

    RaProfileDto getRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    RaProfile getRaProfileEntity(SecuredUUID uuid) throws NotFoundException;

    RaProfileDto editRaProfile(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, EditRaProfileRequestDto dto) throws ConnectorException, AttributeException, NotFoundException;

    void deleteRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    void deleteRaProfile(SecuredUUID uuid) throws NotFoundException;

    void enableRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    void disableRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    void bulkDeleteRaProfile(List<SecuredUUID> uuids);

    void bulkDisableRaProfile(List<SecuredUUID> uuids);

    void bulkEnableRaProfile(List<SecuredUUID> uuids);

    void bulkRemoveAssociatedAcmeProfile(List<SecuredUUID> uuids);

    void bulkRemoveAssociatedScepProfile(List<SecuredUUID> uuids);

    RaProfileAcmeDetailResponseDto getAcmeForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    RaProfileAcmeDetailResponseDto activateAcmeForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid, SecuredUUID acmeProfileUuid, ActivateAcmeForRaProfileRequestDto request) throws ConnectorException, ValidationException, AttributeException, NotFoundException;

    void deactivateAcmeForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    RaProfileScepDetailResponseDto activateScepForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid, SecuredUUID scepProfileUuid, ActivateScepForRaProfileRequestDto request) throws ConnectorException, ValidationException, AttributeException, NotFoundException;

    void deactivateScepForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // CMP protocol management
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Get the RA Profile CMP protocol details
     *
     * @param authorityInstanceUuid UUID of the Authority
     * @param raProfileUuid UUID of the RA Profile
     * @return RA Profile CMP protocol details
     * @throws NotFoundException in case the entity is not found
     */
    RaProfileCmpDetailResponseDto getCmpForRaProfile(
            SecuredParentUUID authorityInstanceUuid,
            SecuredUUID raProfileUuid
    ) throws NotFoundException;

    /**
     * Activate the CMP protocol for the RA Profile
     *
     * @param authorityUuid UUID of the Authority
     * @param uuid UUID of the RA Profile
     * @param cmpProfileUuid UUID of the CMP Profile
     * @param request RaProfileCmpDetailResponseDto
     * @return CMP Profile details
     * @throws ConnectorException in case the connector throws an exception
     * @throws ValidationException in case the validation fails
     * @throws AttributeException in case the attribute is not found
     */
    RaProfileCmpDetailResponseDto activateCmpForRaProfile(
            SecuredParentUUID authorityUuid,
            SecuredUUID uuid,
            SecuredUUID cmpProfileUuid,
            ActivateCmpForRaProfileRequestDto request
    ) throws ConnectorException, ValidationException, AttributeException, NotFoundException;

    /**
     * Deactivate the CMP protocol for the RA Profile
     *
     * @param authorityUuid UUID of the Authority
     * @param uuid UUID of the RA Profile
     * @throws NotFoundException in case the entity is not found
     */
    void deactivateCmpForRaProfile(
            SecuredParentUUID authorityUuid,
            SecuredUUID uuid
    ) throws NotFoundException;

    /**
     * Function to list the RA Profiles associated with the CMP Profiles
     * @param cmpProfileUuid UUID of the CMP Profile
     * @param filter Security filter
     * @return List of RA Profiles associated with the CMP Profiles
     */
    SecuredList<RaProfile> listRaProfilesAssociatedWithCmpProfile(String cmpProfileUuid, SecurityFilter filter);


    /**
     * Remove CMP Profiles from the RA Profiles
     *
     * @param uuids List of RA Profile UUIDs
     */
    void bulkRemoveAssociatedCmpProfile(List<SecuredUUID> uuids);

    List<BaseAttribute> listRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<BaseAttribute> listIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws ConnectorException, NotFoundException;

    /**
     * Save the RA Profile entity to the database
     *
     * @param raProfile RA profile entity
     * @return RA Profile Entity
     */
    RaProfile updateRaProfileEntity(RaProfile raProfile);

    /**
     * Check the compliance for all the certificates associated with the RA Profile
     *
     * @param uuids UUIDs for which the request has to be triggered
     */
    void checkCompliance(List<SecuredUUID> uuids);

    /**
     * Get the number of ra profiles per user for dashboard
     *
     * @return Number of raprofiles
     */
    Long statisticsRaProfilesCount(SecurityFilter filter);

    /**
     * Function to get the list of RA Compliance Profiles from RA Profiles
     *
     * @param authorityUuid UUID of the authority
     * @param raProfileUuid UUID of the RA Profile
     * @return
     */
    List<SimplifiedComplianceProfileDto> getComplianceProfiles(String authorityUuid, String raProfileUuid, SecurityFilter filter) throws NotFoundException;

    /**
     * Function to check if an user has RA profile Access for member certificates
     *
     * @param certificateUuid UUID of the certificate
     * @param raProfileUuid UUID of the RA Profile
     */
    void evaluateCertificateRaProfilePermissions(SecuredUUID certificateUuid, SecuredParentUUID raProfileUuid);

    /**
     * Function to list the RA Profiles associated with the SCEP Profiles
     * @param scepProfileUuid UUID of the SCEP Profile
     * @param filter Security filter
     * @return List of RA Profiles associated with the SCEP Profiles
     */
    SecuredList<RaProfile> listRaProfilesAssociatedWithScepProfile(String scepProfileUuid, SecurityFilter filter);

    RaProfileScepDetailResponseDto getScepForRaProfile(SecuredParentUUID authorityInstanceUuid, SecuredUUID raProfileUuid) throws NotFoundException;

    List<ApprovalProfileDto> getAssociatedApprovalProfiles(String authorityInstanceUuid, String raProfileUuid, SecurityFilter securityFilter) throws NotFoundException;

    ApprovalProfileRelationDto associateApprovalProfile(String authorityInstanceUuid, String raProfileUuid, SecuredUUID approvalProfileUuid) throws NotFoundException;

    void disassociateApprovalProfile(String authorityInstanceUuid, String raProfileUuid, SecuredUUID approvalProfileUuid) throws NotFoundException;

    /**
     * Function to get the list of CA certificates associated with the RA Profile.
     * Certificate chain is returned from the connector if the endpoint is implemented in the connector.
     *
     * @param authorityUuid UUID of the authority
     * @param raProfileUuid UUID of the RA Profile
     * @return List of CA Certificates
     * @throws ConnectorException in case the connector throws an exception
     */
    List<CertificateDetailDto> getAuthorityCertificateChain(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    /**
     * Update configuration of validation of certificates associated with the RA Profile
     * @param authorityUuid UUID of the authority associated with the RA profile
     * @param raProfileUuid UUID of the RA Profile
     * @param request Validation configuration request
     * @return Edited RA Profile
     */
    RaProfileDto updateRaProfileValidationConfiguration(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, RaProfileCertificateValidationSettingsUpdateDto request) throws NotFoundException;
}
