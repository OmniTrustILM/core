package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;
import java.util.UUID;

public interface ComplianceExternalService {

    /**
     * Get the latest compliance check result for the specified resource object
     *
     * @param authorizableResource Resource used as the authorization subject (mapped owning resource)
     * @param authorizableObjectUuid SecuredUUID of the object used as the object-level authorization subject, or
     *                               {@code null} to authorize at resource level only (no per-object scoping)
     * @param resource Resource of the object (used for repository dispatch)
     * @param objectUuid UUID of the object
     * @return ComplianceCheckResultDto containing the result of the latest compliance check
     * @throws NotFoundException if the resource object is not found
     */
    ComplianceCheckResultDto getComplianceCheckResult(SecuredResource authorizableResource, SecuredUUID authorizableObjectUuid, Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Resolves the {@link SecuredUUID} authorization subject.
     *
     * <p>Returns the object's own UUID for resources authorized directly ({@link Resource#CERTIFICATE}, {@link Resource#SECRET}),
     * the owning key UUID for {@link Resource#CRYPTOGRAPHIC_KEY_ITEM}, and {@code null} when the resource has no stable owning object to
     * scope against (e.g. {@link Resource#CERTIFICATE_REQUEST}, which carries its own compliance result and may
     * predate any certificate) or the object cannot be found — in which case authorization is at resource level only.</p>
     *
     * <p><b>Not an authorized read.</b> This only maps a resource and object UUID to the {@link SecuredUUID} used
     * for object-level scoping. It returns the same mapping for every caller and discloses no resource data.
     * Safe under {@code @AnyPrincipalEndpoint}.</p>
     *
     * @param resource Resource of the object
     * @param objectUuid UUID of the object
     * @return SecuredUUID of the authorizable object, or {@code null} for resource-level authorization
     */
    SecuredUUID resolveComplianceAuthorizableObject(Resource resource, UUID objectUuid);

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
     * Check compliance on specified resource objects
     *
     * @param resource Resource of objects checked by compliance
     * @param objectUuids UUIDs of objects to be checked
     */
    void checkResourceObjectsComplianceAsync(Resource resource, List<UUID> objectUuids);
}
