package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.czertainly.core.security.authz.SecuredUUID;

import java.util.List;
import java.util.UUID;

public interface ComplianceInternalService {

    /**
     * Get the latest compliance check result for the specified resource object using the provided compliance result
     *
     * @param resource Resource of the object
     * @param objectUuid UUID of the object
     * @param complianceResult ComplianceResultDto containing the compliance check result data
     * @return ComplianceCheckResultDto containing the result of the latest compliance check
     */
    ComplianceCheckResultDto getComplianceCheckResult(Resource resource, UUID objectUuid, ComplianceResultDto complianceResult);

    /**
     * Get the latest compliance check result for the specified resource object, for internal/system use without authorization.
     *
     * @param resource Resource of the object
     * @param objectUuid UUID of the object
     * @return ComplianceCheckResultDto containing the result of the latest compliance check
     * @throws NotFoundException if the resource object is not found
     */
    ComplianceCheckResultDto getComplianceCheckResult(Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Resolves the {@link SecuredUUID} authorization subject whose owner/group scoping governs read access to the
     * given resource object's compliance result, for use as the object-level argument of
     * {@link ComplianceExternalService#getComplianceCheckResult}.
     *
     * <p>Returns the object's own UUID for resources
     * authorized directly ({@link Resource#CERTIFICATE}, {@link Resource#SECRET}), the owning key UUID for
     * {@link Resource#CRYPTOGRAPHIC_KEY_ITEM}, and {@code null} when the resource has no stable owning object to
     * scope against (e.g. {@link Resource#CERTIFICATE_REQUEST}, which carries its own compliance result and may
     * predate any certificate) or the object cannot be found — in which case authorization is at resource level only.</p>
     *
     * @param resource Resource of the object
     * @param objectUuid UUID of the object
     * @return SecuredUUID of the authorizable object, or {@code null} for resource-level authorization
     */
    SecuredUUID resolveComplianceAuthorizableObject(Resource resource, UUID objectUuid);

    /**
     * Check the compliance for all objects associated with the compliance profiles
     *
     * @param uuids List of UUIDs of the compliance profiles
     * @param resource Filter checked objects by resource
     * @param type Filter checked objects by resource type
     */
    void checkCompliance(List<SecuredUUID> uuids, Resource resource, String type);

    /**
     * Check compliance on specified resource object
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuid UUID of object to be checked
     */
    void checkResourceObjectCompliance(Resource resource, UUID objectUuid);

    /**
     * Check compliance on specified resource object as system user (no user context)
     * Warning: This method should be used only when running compliance check as part of system operations since it bypasses permissions.
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuid UUID of object to be checked
     */
    void checkResourceObjectComplianceAsSystem(Resource resource, UUID objectUuid);

    /**
     * Validate that the specified resource objects exist and support compliance checking, for internal/system use
     * without authorization.
     * Warning: This method should be used only when running compliance validation as part of system operations
     * (e.g. ACME/SCEP/CMP protocol flows) since it bypasses the COMPLIANCE_PROFILE/CHECK_COMPLIANCE permission check.
     *
     * @param resource Resource of the objects
     * @param objectUuids List of UUIDs of the objects to validate
     * @throws ValidationException if the resource does not support compliance check
     * @throws NotFoundException if any of the resource objects is not found
     */
    void checkResourceObjectsComplianceValidationAsSystem(Resource resource, List<UUID> objectUuids) throws ValidationException, NotFoundException;
}
