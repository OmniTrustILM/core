package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.compliance.*;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.ComplianceProfileDto;
import com.czertainly.api.model.core.compliance.ComplianceProfilesListDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;

public interface ComplianceProfileExternalService {

    /**
     * List of all Compliance Profiles available in the system
     *
     * @return List of compliance profiles
     */
    List<ComplianceProfilesListDto> listComplianceProfiles(SecurityFilter filter);

    /**
     * Get the details of a compliance profile
     *
     * @param uuid Uuid of the compliance profile
     * @return Compliance Profile DTO
     * @throws NotFoundException Thrown when the system cannot find the compliance profile for the given Uuid
     */
    ComplianceProfileDto getComplianceProfile(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    /**
     * Create a new compliance profile
     */
    ComplianceProfileDto createComplianceProfile(ComplianceProfileRequestDto request) throws AlreadyExistException, NotFoundException, ValidationException, AttributeException, ConnectorException;

    /**
     * Add a rule to a compliance profile
     */
    ComplianceProfileRuleDto addRule(SecuredUUID uuid, ComplianceRuleAdditionRequestDto request) throws AlreadyExistException, NotFoundException, ValidationException, ConnectorException;

    /**
     * Remove a rule from a compliance profile
     */
    ComplianceProfileRuleDto removeRule(SecuredUUID uuid, ComplianceRuleDeletionRequestDto request) throws NotFoundException, ConnectorException;

    /**
     * Add a group to a compliance profile
     */
    ComplianceProfileDto addGroup(SecuredUUID uuid, ComplianceGroupRequestDto request) throws AlreadyExistException, NotFoundException, ConnectorException;

    /**
     * Delete a group from a compliance profile
     */
    ComplianceProfileDto removeGroup(SecuredUUID uuid, ComplianceGroupRequestDto request) throws NotFoundException, ConnectorException;

    /**
     * Get the list of associated RA Profile to the compliance profile
     */
    List<SimplifiedRaProfileDto> getAssociatedRAProfiles(SecuredUUID uuid);

    /**
     * Delete a compliance profile
     */
    void deleteComplianceProfile(SecuredUUID uuid) throws NotFoundException, ValidationException;

    /**
     * Remove multiple compliance profiles
     */
    List<BulkActionMessageDto> bulkDeleteComplianceProfiles(List<SecuredUUID> uuids) throws NotFoundException, ValidationException;

    /**
     * Remove compliance profiles forcefully.
     */
    List<BulkActionMessageDto> forceDeleteComplianceProfiles(List<SecuredUUID> uuids);

    /**
     * List of all compliance rules for User Interface
     */
    List<ComplianceRulesListResponseDto> getComplianceRules(String complianceProviderUuid, String kind, List<CertificateType> certificateType) throws NotFoundException, ConnectorException;

    /**
     * List of all compliance groups from the compliance providers
     */
    List<ComplianceGroupsListResponseDto> getComplianceGroups(String complianceProviderUuid, String kind) throws NotFoundException, ConnectorException;

    /**
     * Associate a compliance profile to an RA Profile
     */
    void associateProfile(SecuredUUID uuid, RaProfileAssociationRequestDto raProfiles) throws NotFoundException, AlreadyExistException;

    /**
     * Check the compliance for all the certificates associated with the compliance profiles
     */
    void checkCompliance(List<SecuredUUID> uuids);

    /**
     * Disassociate Compliance Profiles from RA Profiles
     */
    void disassociateProfile(SecuredUUID uuid, RaProfileAssociationRequestDto raProfiles) throws NotFoundException;
}
