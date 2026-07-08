package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface ResourceExtensionService {

    /**
     * Function to get the name and uuid dto for the object available in the database. Intended for internal use only without authorization check
     * @return NameAndUuidDto
     */
    NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException;

    /**
     * Function to get the name and uuid dto for the object available in the database. Intended for external use with authorization check
     * @return NameAndUuidDto
     */
    NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException;

    /**
     * Function to get the list of name and uuid dto for the objects available in the database.
     * @return List of NameAndUuidDto
     */
    List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination);

    /**
     * Function to evaluate the permission for the objects and its parents based on the UUID
     * @param uuid UUID of the object
     * @throws NotFoundException when the object with the given UUID is not found
     */
    void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException;

    /**
     * Per-object, calling-user-authorized loader of an object's full connector-consumable attribute blob.
     * <p>
     * This is the AUTHORITY/ENTITY/LOCATION counterpart to the CREDENTIAL two-step gate
     * ({@link #getResourceObjectExternal(SecuredUUID)} + blob build). Unlike the {@code Internal}
     * loaders ({@code getResourceObjectInternal}) and the resource-level list-loaders
     * ({@code loadFullCredentialData(List)} / {@code loadResourceObjectContentData(List)}), implementations
     * MUST carry an object-scoped {@code @ExternalAuthorization} taking the {@link SecuredUUID} so the authorization
     * aspect resolves the concrete object and fails closed when the calling user is not authorized on it. The action
     * is the resource's own object-read gate — {@code DETAIL} for AUTHORITY/ENTITY/LOCATION, and for SECRET
     * {@code GET_SECRET_CONTENT} plus a vault-profile-membership check. This is the load-bearing per-object boundary
     * the reference expander's callback mode resolves through.
     * <p>
     * The default refuses: a kind without a connector-consumable blob has no business being expanded by
     * caller mode and must be treated as a plain pass-through reference by the caller.
     *
     * @param objectUuid object to load, wrapped so the auth aspect can scope the object-read check
     * @return the object's content blob (never a bare name/uuid)
     * @throws NotFoundException     when the object does not exist
     * @throws NotSupportedException when the kind has no authorized blob loader
     */
    default ResourceObjectContentData getAuthorizedObjectAttributes(SecuredUUID objectUuid)
            throws NotFoundException, AttributeException, ConnectorException {
        throw new NotSupportedException("Authorized object attribute loading is not supported for this resource");
    }

}
