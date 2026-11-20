package com.otilm.core.security.authz;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashSet;
import java.util.Set;

/**
 * The part of the OPA method policy ({@code policies/method_policy.rego} in auth-opa-policies) that Core answers
 * without calling OPA.
 * <p>
 * <b>Granted:</b> {@code AllResourcesAllowed} allows every check when {@code permissions.allowAllResources} is true.
 * {@code ActionDeniedForSpecificObject}, the policy's only deny, needs an object of the requested resource with a
 * non-empty {@code deny}, so without such an object OPA authorizes the check whatever it asks.
 * <p>
 * <b>Deferred to OPA:</b> a resource with a denying object, and any permissions shape the policy might read
 * differently, so a grant here is never wider than OPA's.
 * <p>
 * <b>When the policy changes:</b> a deny rule added to or changed in {@code method_policy.rego} must be mirrored here.
 */
record AllResourcesGrant(boolean allowAllResources, Set<String> resourcesWithDeny) {

    static final AllResourcesGrant NONE = new AllResourcesGrant(false, Set.of());

    boolean grants(String resourceName) {
        return allowAllResources && resourceName != null && !resourcesWithDeny.contains(resourceName);
    }

    static AllResourcesGrant of(ObjectMapper objectMapper, String rawPrincipal) {
        JsonNode permissions;
        try {
            permissions = objectMapper.readTree(rawPrincipal).path("permissions");
        } catch (JsonProcessingException | IllegalArgumentException e) {
            return NONE;
        }
        JsonNode allowAllResources = permissions.path("allowAllResources");
        if (!allowAllResources.isBoolean() || !allowAllResources.booleanValue()) {
            return NONE;
        }
        JsonNode resources = permissions.path("resources");
        if (isAbsent(resources)) {
            return new AllResourcesGrant(true, Set.of());
        }
        if (!resources.isArray()) {
            return NONE;
        }
        Set<String> resourcesWithDeny = new HashSet<>();
        for (JsonNode resource : resources) {
            JsonNode name = resource.path("name");
            if (name.isTextual() && deniesAnObject(resource.path("objects"))) {
                resourcesWithDeny.add(name.textValue());
            }
        }
        return new AllResourcesGrant(true, Set.copyOf(resourcesWithDeny));
    }

    private static boolean deniesAnObject(JsonNode objects) {
        if (isAbsent(objects)) {
            return false;
        }
        if (!objects.isArray()) {
            return true;
        }
        for (JsonNode object : objects) {
            JsonNode deny = object.path("deny");
            if (!isAbsent(deny) && !(deny.isArray() && deny.isEmpty())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isAbsent(JsonNode node) {
        return node.isMissingNode() || node.isNull();
    }
}
