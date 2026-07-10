package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Fully resolved inputs for a single authorization check.
 */
public record AuthorizationRequest(
        Map<String, String> properties,
        List<SecuredUUID> objectUuids,
        List<SecuredUUID> parentUuids,
        boolean hasSecurityFilter,
        Optional<Class<ParentUUIDGetter>> parentUuidGetterClass,
        String contextLabel) {

    public AuthorizationRequest {
        properties = properties == null ? Map.of() : Map.copyOf(properties);
        objectUuids = objectUuids == null ? List.of() : List.copyOf(objectUuids);
        parentUuids = parentUuids == null ? List.of() : List.copyOf(parentUuids);
        Objects.requireNonNull(parentUuidGetterClass,
                "parentUuidGetterClass must not be null; pass Optional.empty()");
    }

    /**
     * Builds the request for a direct {@code enforce(resource, action, uuids)} call.
     */
    public static AuthorizationRequest forDirectCheck(Resource resource, ResourceAction action, List<SecuredUUID> objectUuids) {
        Map<String, String> properties = Map.of(
                AuthorizationProperties.ACTION, action.getCode(),
                AuthorizationProperties.NAME, resource.getCode(),
                AuthorizationProperties.PARENT_ACTION, ResourceAction.NONE.getCode(),
                AuthorizationProperties.PARENT_NAME, Resource.NONE.getCode());
        return new AuthorizationRequest(
                properties,
                objectUuids,
                List.of(),
                false,
                Optional.empty(),
                "%s:%s".formatted(resource.getCode(), action.getCode()));
    }
}
