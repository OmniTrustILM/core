package com.czertainly.core.service;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.czertainly.core.security.authz.SecuredUUID;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface ComplianceService {


    /**
     * Get the latest compliance check result for the specified resource object
     *
     * @param resource Resource of the object
     * @param objectUuid UUID of the object
     * @return ComplianceCheckResultDto containing the result of the latest compliance check
     * @throws NotFoundException if the resource object is not found
     */
    ComplianceCheckResultDto getComplianceCheckResult(Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Get the latest compliance check result for the specified resource object using the provided compliance result
     *
     * @param resource Resource of the object
     * @param objectUuid UUID of the
     * @param complianceResult ComplianceResultDto containing the compliance check result data
     * @return ComplianceCheckResultDto containing the result of the latest compliance check
     */
    ComplianceCheckResultDto getComplianceCheckResult(Resource resource, UUID objectUuid, ComplianceResultDto complianceResult);


    /**
     * Validate Check compliance request for specified compliance profiles
     *
     * @param uuids List of UUIDs of the compliance profiles
     * @param resource Filter checked objects by resource
     * @param type Filter checked objects by resource type
     * @throws ValidationException if validation fails
     * @throws NotFoundException if compliance profile is not found
     */
    void checkComplianceValidation(List<SecuredUUID> uuids, Resource resource, String type) throws ValidationException, NotFoundException;

    /**
     * Check the compliance for all objects associated with the compliance profiles in asynchronous way
     *
     * @param uuids List of UUIDs of the compliance profiles
     * @param resource Filter checked objects by resource
     * @param type Filter checked objects by resource type
     */
    void checkComplianceAsync(List<SecuredUUID> uuids, Resource resource, String type);


    /**
     * Check the compliance for all objects associated with the compliance profiles
     *
     * @param uuids List of UUIDs of the compliance profiles
     * @param resource Filter checked objects by resource
     * @param type Filter checked objects by resource type
     */
    void checkCompliance(List<SecuredUUID> uuids, Resource resource, String type);

    /**
     * Validate Check compliance request for specified resource objects
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuids UUIDs of objects to be checked
     * @throws ValidationException if validation fails
     * @throws NotFoundException if resource object is not found
     */
    void checkResourceObjectsComplianceValidation(Resource resource, List<UUID> objectUuids) throws ValidationException, NotFoundException;

    /**
     * Check compliance on specified resource object
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuid UUID of object to be checked
     */
    void checkResourceObjectComplianceAsync(Resource resource, UUID objectUuid);

    /**
     * Check compliance on specified resource object as system user (no user context)
     * Warning: This method should be used only when running compliance check as part of system operations since it bypasses permissions.
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuid UUID of object to be checked
     */
    void checkResourceObjectComplianceAsSystem(Resource resource, UUID objectUuid);

    /**
     * Check compliance on specified resource objects
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuids UUIDs of objects to be checked
     */
    void checkResourceObjectsComplianceAsync(Resource resource, List<UUID> objectUuids);


    /**
     * Check compliance on specified resource object
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuid UUID of object to be checked
     */
    void checkResourceObjectCompliance(Resource resource, UUID objectUuid);

    /**
     * Remove rule UUIDs from the JSONB compliance_result column of all subjects associated with the given compliance profile.
     * This prevents stale rule results from affecting future compliance status calculations when compliance is checked by profiles.
     * The compliance status is not recalculated — it will be corrected by the next scheduled compliance check.
     *
     * @param complianceProfileUuid UUID of the compliance profile from which the rules were removed
     * @param ruleResource          resource of the rule identifying the compliance subject type (e.g. CERTIFICATE, SECRET)
     * @param ruleUuids             UUIDs of the rules to remove from results
     * @param connectorUuid         UUID of the compliance provider connector (null for internal rules)
     * @param kind                  kind identifier of the compliance provider (null for internal rules)
     */
    void removeRulesFromComplianceResults(UUID complianceProfileUuid, Resource ruleResource, Set<UUID> ruleUuids, UUID connectorUuid, String kind);

    /**
     * Remove all rule UUIDs belonging to a provider group from the JSONB compliance_result column of all subjects
     * associated with the given compliance profile. Fetches the group's rules from the compliance provider.
     *
     * @param complianceProfileUuid UUID of the compliance profile from which the group was removed
     * @param ruleResource          resource of the group identifying the compliance subject type
     * @param groupUuid             UUID of the group whose rule results should be removed
     * @param connectorUuid         UUID of the compliance provider connector
     * @param kind                  kind identifier of the compliance provider
     */
    void removeGroupRulesFromComplianceResults(UUID complianceProfileUuid, Resource ruleResource, UUID groupUuid, UUID connectorUuid, String kind) throws ConnectorException, NotFoundException;

}
