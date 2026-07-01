package com.otilm.core.service.v2;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.compliance.v2.*;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.v2.ComplianceGroupListDto;
import com.otilm.api.model.core.compliance.v2.ComplianceProfileDto;
import com.otilm.api.model.core.compliance.v2.ComplianceProfileListDto;
import com.otilm.api.model.core.compliance.v2.ComplianceRuleListDto;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface ComplianceProfileExternalService {
    /**
     * List of all Compliance Profiles available in the system
     *
     * @return List of compliance profiles
     */
    List<ComplianceProfileListDto> listComplianceProfiles(SecurityFilter filter);

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
     *
     * @param request Request containing the attributes to create a new compliance profile. See {@link ComplianceProfileRequestDto}
     * @return DTO of the new compliance profile that was created
     * @throws AlreadyExistException Thrown when an existing compliance profile is found with the same name
     * @throws ValidationException   Thrown when the attributes validations are failed for a rule in the request
     */
    ComplianceProfileDto createComplianceProfile(ComplianceProfileRequestDto request) throws AlreadyExistException, ConnectorException, NotFoundException, AttributeException;

    /**
     * Update compliance profile
     *
     * @param request Request containing the attributes to update compliance profile. See {@link ComplianceProfileUpdateRequestDto}
     * @return DTO of compliance profile that was updated
     * @throws NotFoundException Thrown when the system cannot find the compliance profile for the given Uuid
     * @throws ValidationException   Thrown when the attributes validations are failed for a rule in the request
     */
    ComplianceProfileDto updateComplianceProfile(SecuredUUID uuid, ComplianceProfileUpdateRequestDto request) throws NotFoundException, ConnectorException, AttributeException;

    /**
     * Delete a compliance profile
     *
     * @param uuid UUID of the compliance profile
     * @throws NotFoundException   Thrown when the system is not able to find the compliance profile for the given UUID
     */
    void deleteComplianceProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Remove multiple compliance profiles
     *
     * @param uuids List of Uuids of the profiles to be deleted
     * @return List of dependencies for profiles that has RA Profile associations. See {@link BulkActionMessageDto}
     * @throws ValidationException Thrown when the profiles are dependencies for other objects
     * @throws NotFoundException   Thrown when a Rule or Group is not found
     */
    List<BulkActionMessageDto> bulkDeleteComplianceProfiles(List<SecuredUUID> uuids);

    /**
     * Remove compliance profiles forcefully. This methods makes removes the object dependencies and set them null.
     *
     * @param uuids Uuids of the compliance profiles to be deleted forcefully.
     * @return
     */
    List<BulkActionMessageDto> forceDeleteComplianceProfiles(List<SecuredUUID> uuids);

    /**
     * List compliance rules by specified criteria
     *
     * @param connectorUuid connector UUID. When not provided, internal (workflow rules are listed)
     * @param kind
     * @param resource resource of the rule
     * @param type
     * @param format
     * @return
     * @throws NotFoundException
     */
    List<ComplianceRuleListDto> getComplianceRules(UUID connectorUuid, String kind, Resource resource, String type, String format) throws NotFoundException, ConnectorException;

    /**
     * List compliance groups by specified criteria
     *
     * @param connectorUuid
     * @param kind
     * @param resource resource of the group
     * @return
     * @throws NotFoundException
     */
    List<ComplianceGroupListDto> getComplianceGroups(UUID connectorUuid, String kind, Resource resource) throws NotFoundException, ConnectorException;

    /**
     * @param groupUuid
     * @param connectorUuid
     * @param kind
     * @return
     * @throws NotFoundException
     * @throws ConnectorException
     */
    List<ComplianceRuleListDto> getComplianceGroupRules(UUID groupUuid, UUID connectorUuid, String kind) throws NotFoundException, ConnectorException;

    /**
     * Create a new internal compliance rule
     *
     * @param request Request containing the attributes to create a new internal compliance rule. See {@link ComplianceInternalRuleRequestDto}
     * @return DTO of the new internal compliance rule that was created
     * @throws AlreadyExistException Thrown when an existing internal compliance rule is found with the same name
     * @throws ValidationException   Thrown when the attributes validations are failed for a rule in the request
     */
    ComplianceRuleListDto createComplianceInternalRule(ComplianceInternalRuleRequestDto request) throws AlreadyExistException;

    /**
     * Update an existing internal compliance rule
     *
     * @param internalRuleUuid UUID of the internal compliance rule to be updated
     * @param request Request containing the attributes to update the internal compliance rule. See {@link ComplianceInternalRuleRequestDto}
     * @return DTO of the internal compliance rule that was updated
     * @throws NotFoundException Thrown when the system cannot find the internal compliance rule for the given Uuid
     * @throws ValidationException   Thrown when the attributes validations are failed for a rule in the request
     */
    ComplianceRuleListDto updateComplianceInternalRule(UUID internalRuleUuid, ComplianceInternalRuleRequestDto request) throws NotFoundException;

    /**
     * Delete an internal compliance rule
     *
     * @param internalRuleUuid UUID of the internal compliance rule to be deleted
     * @throws NotFoundException Thrown when the system cannot find the internal compliance rule for the given Uuid
     */
    void deleteComplianceInternalRule(UUID internalRuleUuid) throws NotFoundException;

    /**
     * Patch compliance profile rules
     *
     * @param uuid UUID of the compliance profile
     * @param request Request containing the rules to be added/removed from the compliance profile. See {@link ComplianceProfileRulesPatchRequestDto}
     * @throws NotFoundException Thrown when the system cannot find the compliance profile for the given Uuid
     * @throws ConnectorException Thrown when the system cannot communicate with the connector
     */
    void patchComplianceProfileRules(SecuredUUID uuid, ComplianceProfileRulesPatchRequestDto request) throws NotFoundException, ConnectorException;

    /**
     * Patch compliance profile groups
     *
     * @param uuid UUID of the compliance profile
     * @param request Request containing the groups to be added/removed from the compliance profile. See {@link ComplianceProfileGroupsPatchRequestDto}
     * @throws NotFoundException Thrown when the system cannot find the compliance profile for the given Uuid
     * @throws ConnectorException Thrown when the system cannot communicate with the connector
     */
    void patchComplianceProfileGroups(SecuredUUID uuid, ComplianceProfileGroupsPatchRequestDto request) throws ConnectorException, NotFoundException;

    /**
     * Get the list of associated resource objects to the compliance profile
     *
     * @param uuid Uuid of the compliance profile
     * @return List of resource objects associated with the compliance profile. {@link ResourceObjectDto}
     * @throws NotFoundException * @throws NotFoundException Thrown when compliance profile is not found
     */
    List<ResourceObjectDto> getAssociations(SecuredUUID uuid) throws NotFoundException;

    /**
     * List compliance profiles associated with resource object
     *
     * @param resource
     * @param associationObjectUuid
     * @return
     * @throws NotFoundException
     */
    List<ComplianceProfileListDto> getAssociatedComplianceProfiles(Resource resource, UUID associationObjectUuid);

    /**
     * Associate a compliance profile to resource object
     *
     * @param uuid uuid of compliance profile
     * @param resource
     * @param associationObjectUuid
     * @throws NotFoundException
     */
    void associateComplianceProfile(SecuredUUID uuid, Resource resource, UUID associationObjectUuid) throws NotFoundException, AlreadyExistException;

    /**
     * Disassociate a compliance profile from resource object
     *
     * @param uuid uuid of compliance profile
     * @param resource
     * @param associationObjectUuid
     * @throws NotFoundException
     */
    void disassociateComplianceProfile(SecuredUUID uuid, Resource resource, UUID associationObjectUuid) throws NotFoundException;
}
