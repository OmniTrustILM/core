package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.cmp.CmpProfileEditRequestDto;
import com.otilm.api.model.client.cmp.CmpProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.cmp.CmpProfileDetailDto;
import com.otilm.api.model.core.cmp.CmpProfileDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface CmpProfileService extends ResourceExtensionService {

    // TODO: Update the return type and parameters of the methods according to the business logic

    /**
     * List all available CMP Profiles
     * @param filter Security Filter
     * @return List of available CMP Profiles
     */
    List<CmpProfileDto> listCmpProfile(SecurityFilter filter);

    /**
     * Get the details of CMP Profile
     * @param cmpProfileUuid UUID of the CMP Profile
     * @return Details of the CMP Profile
     * @throws NotFoundException when the CMP profile with the given UUID is not found
     */
    CmpProfileDetailDto getCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException;

    /**
     * Create a new CMP Profile
     * @param request DTO containing the details needed for the creation of the CMP Profile
     * @return Details of the created CMP Profile
     * @throws AlreadyExistException when the CMP Profile already exists
     * @throws NotFoundException when the RA Profile with the requested UUID is not found
     * @throws ValidationException When the validation fails for the attributes or any other parameters in the request
     */
    CmpProfileDetailDto createCmpProfile(CmpProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException;

    /**
     * Update existing CMP Profile
     * @param cmpProfileUuid UUID of the CMP Profile
     * @param request DTO containing the details needed for updating the CMP Profile
     * @return Details of updated CMP Profile
     * @throws NotFoundException when the RA Profile with the requested UUID is not found
     * @throws ValidationException When the validation fails for the attributes or any other parameters in the request
     */
    CmpProfileDetailDto editCmpProfile(SecuredUUID cmpProfileUuid, CmpProfileEditRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    /**
     * Delete CMP Profile
     * @param cmpProfileUuid UUID of the CMP Profile to be deleted
     * @throws NotFoundException when the CMP Profile with the given UUID is not found
     * @throws ValidationException When the validation fails for the attributes ot any other parameters in the request
     */
    void deleteCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException, ValidationException;

    /**
     * Delete multiple CMP Profiles
     * @param cmpProfileUuids UUIDs of the CMP Profiles to be deleted
     * @return Messages regarding the failed deletion of the profiles
     */
    List<BulkActionMessageDto> bulkDeleteCmpProfile(List<SecuredUUID> cmpProfileUuids);

    /**
     * Delete multiple CMP Profiles forcefully
     * @param cmpProfileUuids UUIDs of the CMP Profiles to be deleted
     * @return Messages regarding the failed deletion of the profiles
     */
    List<BulkActionMessageDto> bulkForceRemoveCmpProfiles(List<SecuredUUID> cmpProfileUuids) throws NotFoundException, ValidationException;

    /**
     * Enable CMP Profile
     * @param cmpProfileUuid UUID of the CMP Profile to be enabled
     * @throws NotFoundException when the CMP Profile with the given UUID is not found
     */
    void enableCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException;

    /**
     * Enable multiple CMP Profiles
     * @param cmpProfileUuids UUID of the CMP Profiles to be enabled
     */
    void bulkEnableCmpProfile(List<SecuredUUID> cmpProfileUuids);

    /**
     * Disable CMP Profile
     * @param cmpProfileUuid UUID of the CMP Profile to be disabled
     * @throws NotFoundException when the CMP Profile with the given UUID is not found
     */
    void disableCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException;

    /**
     * Disable multiple CMP Profiles
     * @param cmpProfileUuids UUID of the CMP Profiles to be disabled
     */
    void bulkDisableCmpProfile(List<SecuredUUID> cmpProfileUuids);

    /**
     * Update RA Profile for the CMP Profile
     * @param cmpProfileUuid UUID of the CMP Profile
     * @param raProfileUuid UUID of the RA Profile
     * @throws NotFoundException When the given CMP Profile or RA Profile is not found
     */
    void updateRaProfile(SecuredUUID cmpProfileUuid, String raProfileUuid) throws NotFoundException;

    /**
     * List certificates eligible for signing of CMP responses
     * @return List of available signing certificates
     */
    List<CertificateDto> listCmpSigningCertificates();

}
