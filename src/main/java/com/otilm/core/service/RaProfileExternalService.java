package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRelationDto;
import com.otilm.api.model.client.compliance.SimplifiedComplianceProfileDto;
import com.otilm.api.model.client.raprofile.ActivateAcmeForRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.ActivateCmpForRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.ActivateEstForRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.ActivateScepForRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.AddRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.EditRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.RaProfileAcmeDetailResponseDto;
import com.otilm.api.model.client.raprofile.RaProfileCmpDetailResponseDto;
import com.otilm.api.model.client.raprofile.RaProfileEstDetailResponseDto;
import com.otilm.api.model.client.raprofile.RaProfileScepDetailResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesUpdateDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.raprofile.RaProfileDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RaProfileExternalService {

    List<RaProfileDto> listRaProfiles(SecurityFilter filter, Optional<Boolean> enabled);

    RaProfileDto addRaProfile(SecuredParentUUID authorityUuid, AddRaProfileRequestDto dto) throws AlreadyExistException,
            ValidationException, ConnectorException, AttributeException, NotFoundException;

    RaProfileDto getRaProfile(SecuredUUID uuid) throws NotFoundException;

    RaProfileDto getRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    RaProfileDto editRaProfile(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, EditRaProfileRequestDto dto)
            throws ConnectorException, AttributeException, NotFoundException;

    void deleteRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    void deleteRaProfile(SecuredUUID uuid) throws NotFoundException;

    void enableRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    void disableRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    void bulkDeleteRaProfile(List<SecuredUUID> uuids);

    void bulkDisableRaProfile(List<SecuredUUID> uuids);

    void bulkEnableRaProfile(List<SecuredUUID> uuids);

    RaProfileAcmeDetailResponseDto getAcmeForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid)
            throws NotFoundException;

    RaProfileAcmeDetailResponseDto activateAcmeForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid,
            SecuredUUID acmeProfileUuid, ActivateAcmeForRaProfileRequestDto request)
            throws ConnectorException, ValidationException, AttributeException, NotFoundException;

    void deactivateAcmeForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    RaProfileScepDetailResponseDto activateScepForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid,
            SecuredUUID scepProfileUuid, ActivateScepForRaProfileRequestDto request)
            throws ConnectorException, ValidationException, AttributeException, NotFoundException;

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
    RaProfileCmpDetailResponseDto getCmpForRaProfile(SecuredParentUUID authorityInstanceUuid, SecuredUUID raProfileUuid)
            throws NotFoundException;

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
    RaProfileCmpDetailResponseDto activateCmpForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid,
            SecuredUUID cmpProfileUuid, ActivateCmpForRaProfileRequestDto request)
            throws ConnectorException, ValidationException, AttributeException, NotFoundException;

    /**
     * Deactivate the CMP protocol for the RA Profile
     *
     * @param authorityUuid UUID of the Authority
     * @param uuid UUID of the RA Profile
     * @throws NotFoundException in case the entity is not found
     */
    void deactivateCmpForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    /**
     * Get the RA Profile EST protocol details
     *
     * @param authorityUuid UUID of the Authority
     * @param uuid UUID of the RA Profile
     * @param origin scheme, host and port the EST URL of the RA Profile is composed on
     * @return RA Profile EST protocol details, only {@code estAvailable} is set while EST is not active
     * @throws NotFoundException in case the RA Profile is not found, also when it is not under the authority
     */
    RaProfileEstDetailResponseDto getEstForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid, String origin)
            throws NotFoundException;

    /**
     * Activate the EST protocol for the RA Profile, which is then served under its name as the EST label. The EST
     * Profile's UUID is not a {@link SecuredUUID}: the authorization of this method would take it for one of the RA
     * Profiles it is checked on. The caller needs DETAIL on the EST Profile, checked before it is looked up.
     *
     * @param authorityUuid UUID of the Authority
     * @param uuid UUID of the RA Profile
     * @param estProfileUuid UUID of the EST Profile
     * @param request Attributes to issue certificates with
     * @param origin scheme, host and port the EST URL of the RA Profile is composed on
     * @return RA Profile EST protocol details
     * @throws ConnectorException in case the connector throws an exception
     * @throws ValidationException in case the RA Profile name cannot be an EST label or is already the label of an EST
     * Profile, the authority of the RA Profile has no connector or was given another one while the issue attributes
     * were validated, or the attributes are invalid
     * @throws AttributeException in case the attribute is not found
     * @throws NotFoundException in case the RA Profile or the EST Profile is not found, also when the RA Profile is not
     * under the authority or was moved to another one while the issue attributes were validated
     */
    RaProfileEstDetailResponseDto activateEstForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid,
            UUID estProfileUuid, ActivateEstForRaProfileRequestDto request, String origin)
            throws ConnectorException, ValidationException, AttributeException, NotFoundException;

    /**
     * Deactivate the EST protocol for the RA Profile
     *
     * @param authorityUuid UUID of the Authority
     * @param uuid UUID of the RA Profile
     * @throws NotFoundException in case the RA Profile is not found, also when it is not under the authority
     */
    void deactivateEstForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID uuid) throws NotFoundException;

    List<BaseAttribute> listRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID uuid)
            throws ConnectorException, NotFoundException;

    List<BaseAttribute> listIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID uuid)
            throws ConnectorException, NotFoundException;

    List<BaseAttribute> listRenewCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID uuid)
            throws ConnectorException, NotFoundException;

    List<BaseAttribute> listIdentifyCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID uuid)
            throws ConnectorException, NotFoundException;

    /**
     * Check the compliance for all the certificates associated with the RA Profile
     *
     * @param uuids UUIDs for which the request has to be triggered
     */
    void checkCompliance(List<SecuredUUID> uuids);

    /**
     * Function to get the list of RA Compliance Profiles from RA Profiles
     *
     * @param authorityUuid UUID of the authority
     * @param raProfileUuid UUID of the RA Profile
     * @return
     */
    List<SimplifiedComplianceProfileDto> getComplianceProfiles(String authorityUuid, String raProfileUuid,
            SecurityFilter filter) throws NotFoundException;

    RaProfileScepDetailResponseDto getScepForRaProfile(SecuredParentUUID authorityInstanceUuid,
            SecuredUUID raProfileUuid) throws NotFoundException;

    List<ApprovalProfileDto> getAssociatedApprovalProfiles(String authorityInstanceUuid, String raProfileUuid,
            SecurityFilter securityFilter) throws NotFoundException;

    ApprovalProfileRelationDto associateApprovalProfile(String authorityInstanceUuid, String raProfileUuid,
            SecuredUUID approvalProfileUuid) throws NotFoundException;

    void disassociateApprovalProfile(String authorityInstanceUuid, String raProfileUuid,
            SecuredUUID approvalProfileUuid) throws NotFoundException;

    /**
     * Function to get the list of CA certificates associated with the RA Profile. Certificate chain is returned from
     * the connector if the endpoint is implemented in the connector.
     *
     * @param authorityUuid UUID of the authority
     * @param raProfileUuid UUID of the RA Profile
     * @return List of CA Certificates
     * @throws ConnectorException in case the connector throws an exception
     */
    List<CertificateDetail> getAuthorityCertificateChain(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    /**
     * Update configuration of validation of certificates associated with the RA Profile
     *
     * @param authorityUuid UUID of the authority associated with the RA profile
     * @param raProfileUuid UUID of the RA Profile
     * @param request Validation configuration request
     * @return Edited RA Profile
     */
    RaProfileDto updateRaProfileValidationConfiguration(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            RaProfileCertificateValidationSettingsUpdateDto request) throws NotFoundException;

    /**
     * Update the static request-attribute configuration (definitions, merge mode, value-source bindings, strictness) of
     * the RA Profile.
     *
     * @param authorityUuid UUID of the authority associated with the RA profile
     * @param raProfileUuid UUID of the RA Profile
     * @param request Request-attribute configuration request
     * @return Edited RA Profile
     */
    RaProfileDto updateRaProfileRequestAttributesConfiguration(SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid, RaProfileCertificateRequestAttributesUpdateDto request) throws NotFoundException;
}
