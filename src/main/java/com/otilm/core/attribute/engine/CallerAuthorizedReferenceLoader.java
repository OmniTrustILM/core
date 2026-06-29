package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.core.security.authz.SecuredUUID;

/**
 * A per-object, calling-user-authorized blob loader for one {@code AttributeResource} kind.
 * <p>
 * The argument is always a {@link SecuredUUID} so the implementation's {@code @ExternalAuthorization(<KIND>, DETAIL)}
 * aspect resolves and authorizes the concrete object before any blob is read. This typed contract is the
 * fail-open-prevention device: the registry can only hold values of this type, so a future
 * kind cannot be wired to a non-{@code SecuredUUID}, non-DETAIL finder by accident.
 */
@FunctionalInterface
interface CallerAuthorizedReferenceLoader {

    /**
     * Authorize the ambient caller for {@code DETAIL} on {@code uuid} and return the object's connector-consumable
     * blob. Implementations must NOT swallow the authorization denial — it propagates so expansion fails closed.
     */
    ResourceObjectContentData loadAuthorized(SecuredUUID uuid)
            throws NotFoundException, AttributeException, ConnectorException;
}
