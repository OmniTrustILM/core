package com.czertainly.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.scep.ScepProfileEditRequestDto;
import com.otilm.api.model.client.scep.ScepProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.scep.ScepProfileDetailDto;
import com.otilm.api.model.core.scep.ScepProfileDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;

public interface ScepProfileService extends ResourceExtensionService {

    /**
     * List all available SCEP Profiles
     * @param filter Security Filter
     * @return List of available SCEP Profiles
     */
    List<ScepProfileDto> listScepProfile(SecurityFilter filter);

    /**
     * Get the detail of an SCEP Profile
     * @param uuid UUID of the SCEP profile
     * @return Detail of the SCEP Profile
     * @throws NotFoundException when the SCEP profile with the given UUID is not found in the system
     */
    ScepProfileDetailDto getScepProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Create a new SCEP Profile
     * @param request DTO containing the needed parameters for creating the new SCEP Profile
     * @return Detail of the newly created SCEP Profile
     * @throws AlreadyExistException when the SCEP profile already exists
     * @throws NotFoundException when the profile with the requested UUID is not found
     * @throws ValidationException When the validation fails for the attributes or any other parameters in the request
     */
    ScepProfileDetailDto createScepProfile(ScepProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException;

    /**
     * Update SCEP Profile
     * @param uuid UUID of the SCEP Profile
     * @param request DTO containing the details needed for the updating the SCEP Profile
     * @return Updated details for the SCEP Profile
     * @throws AlreadyExistException when the SCEP profile already exists
     * @throws NotFoundException when the profile with the requested UUID is not found
     * @throws ValidationException When the validation fails for the attributes or any other parameters in the request
     */
    ScepProfileDetailDto editScepProfile(SecuredUUID uuid, ScepProfileEditRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    /**
     * Delete SCEP Profile
     * @param uuid UUID of the SCEP Profile to be deleted
     * @throws NotFoundException when the SCEP Profile with the given UUID is not found
     * @throws ValidationException When the validation fails for the attributes ot any other parameters in the request
     */
    void deleteScepProfile(SecuredUUID uuid) throws NotFoundException, ValidationException;

    /**
     * Delete multiple SCEP Profiles
     * @param uuids UUIDs of the SCEP Profiles to be deleted
     * @return Messages regarding the failed deletion of the profiles
     */
    List<BulkActionMessageDto> bulkDeleteScepProfile(List<SecuredUUID> uuids);

    /**
     * Delete multiple SCEP Profiles forcefully
     * @param uuids UUIDs of the SCEP Profiles to be deleted
     * @return Messages regarding the failed deletion of the profiles
     */
    List<BulkActionMessageDto> bulkForceRemoveScepProfiles(List<SecuredUUID> uuids);

    /**
     * Enable SCEP Profile
     * @param uuid UUID of the SCEP Profile to be enabled
     * @throws NotFoundException when the SCEP Profile with the given UUID is not found
     */
    void enableScepProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Enable multiple SCEP Profiles
     * @param uuids UUID of the SCEP Profiles to be enabled
     */
    void bulkEnableScepProfile(List<SecuredUUID> uuids);

    /**
     * Disable SCEP Profile
     * @param uuid UUID of the SCEP Profile to be disabled
     * @throws NotFoundException when the SCEP Profile with the given UUID is not found
     */
    void disableScepProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Disable multiple SCEP Profiles
     * @param uuids UUID of the SCEP Profiles to be disabled
     */
    void bulkDisableScepProfile(List<SecuredUUID> uuids);

    /**
     * Update the RA Profile for the SCEP Profile
     * @param uuid UUID of the SCEP Profile
     * @param raProfileUuid UUID of the RA Profile
     * @throws NotFoundException When the SCEP or RA Profile is not found
     */
    void updateRaProfile(SecuredUUID uuid, String raProfileUuid) throws NotFoundException;

    /**
     * List certificates eligible for CA certificate of SCEP requests
     * @param intuneEnabled flag to return certificates that are eligible for Intune integration
     * @return List of available CA certificates
     */
    List<CertificateDto> listScepCaCertificates(boolean intuneEnabled);
}
