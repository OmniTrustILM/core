package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.AnonymousPrincipal;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.util.AuthHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Single implementation of the OmniTrust authorization semantics: principal dispatch, OPA request construction,
 * parent-resource-first check, group/owner-association fallback, and deny-on-error.
 *
 * <p>Operates purely on a resolved {@link AuthorizationRequest}; it has no knowledge of annotations or Spring AOP.
 * Shared by {@link ExternalMethodAuthorizationManager} (declarative path) and {@link AuthorizationEnforcerImpl} (imperative path).
 */
@Component
class ExternalAuthorizationCore {

    private final Log log = LogFactory.getLog(this.getClass());

    private static final String NAME_PROP_NAME = "name";
    private static final String ACTION_PROP_NAME = "action";
    private static final String PARENT_NAME_PROP_NAME = "parentName";
    private static final String PARENT_ACTION_PROP_NAME = "parentAction";

    private final OpaClient opaClient;
    private final ObjectMapper om;
    private final GroupAssociationRepository groupAssociationRepository;
    private final OwnerAssociationRepository ownerAssociationRepository;

    ExternalAuthorizationCore(OpaClient opaClient, ObjectMapper om,
                              GroupAssociationRepository groupAssociationRepository,
                              OwnerAssociationRepository ownerAssociationRepository) {
        this.opaClient = opaClient;
        this.om = om;
        this.groupAssociationRepository = groupAssociationRepository;
        this.ownerAssociationRepository = ownerAssociationRepository;
    }

    AuthorizationDecision decide(Authentication authentication, AuthorizationRequest request) {
        if (!(authentication instanceof PlatformAuthenticationToken || authentication instanceof AnonymousAuthenticationToken)) {
            log.trace("Authentication is not of type 'PlatformAuthenticationToken' or 'AnonymousAuthenticationToken'. Cannot authorize.");
            return new AuthorizationDecision(false);
        }
        if (authentication instanceof PlatformAuthenticationToken token) {
            AuthorizationDecision result = check(token.getPrincipal().getRawData(), request);
            if (!result.isGranted()) {
                try {
                    return checkGroupOwnerAssociations(token.getPrincipal(), request);
                } catch (Exception e) {
                    log.error("Unable to evaluate group/owner associations for '%s'. Voting to deny access.".formatted(request.contextLabel()), e);
                    return new AuthorizationDecision(false);
                }
            }
            return result;
        }
        try {
            return check(om.writeValueAsString(new AnonymousPrincipal(authentication.getName())), request);
        } catch (JsonProcessingException e) {
            log.error("An error occurred during authorization on '%s'. Access will be denied.".formatted(request.contextLabel()), e);
            return new AuthorizationDecision(false);
        }
    }

    private AuthorizationDecision check(String principal, AuthorizationRequest request) {
        try {
            Map<String, String> properties = new HashMap<>(request.properties());
            Optional<ParentUUIDGetter> parentUUIDGetter = instantiateParentUUIDGetter(request.parentUuidGetterClass());
            if (!Resource.NONE.getCode().equals(properties.get(PARENT_NAME_PROP_NAME))) {
                AuthorizationDecision result = checkResource(principal, request, properties, parentUUIDGetter, true);
                if (!result.isGranted()) {
                    AuthHelper.setDeniedPermissionResourceAction(properties.get(PARENT_NAME_PROP_NAME), properties.get(PARENT_ACTION_PROP_NAME));
                    return result;
                }
            }
            return checkResource(principal, request, properties, parentUUIDGetter, false);
        } catch (Exception e) {
            log.error("Unable verify access to '%s'. Voting to deny access.".formatted(request.contextLabel()), e);
            return new AuthorizationDecision(false);
        }
    }

    private AuthorizationDecision checkResource(String principal, AuthorizationRequest request, Map<String, String> properties,
                                                Optional<ParentUUIDGetter> parentUUIDGetter, boolean parentResource) {
        Map<String, String> checkProperties = properties;
        if (parentResource) {
            Map<String, String> parentProperties = new HashMap<>(properties);
            parentProperties.put(NAME_PROP_NAME, properties.get(PARENT_NAME_PROP_NAME));
            parentProperties.put(ACTION_PROP_NAME, properties.get(PARENT_ACTION_PROP_NAME));
            checkProperties = parentProperties;
        }
        checkProperties.remove(PARENT_NAME_PROP_NAME);
        checkProperties.remove(PARENT_ACTION_PROP_NAME);

        OpaRequestedResource resource = new OpaRequestedResource(checkProperties);
        List<SecuredUUID> objectUUIDs = parentResource ? request.parentUuids() : request.objectUuids();

        if (!parentResource && parentUUIDGetter.isPresent()) {
            if (objectUUIDs.isEmpty()) {
                log.error("ParentUUIDGetter specified but no object uuids were found. Access to '%s' will be denied.".formatted(request.contextLabel()));
                AuthHelper.setDeniedPermissionResourceAction(checkProperties.get(NAME_PROP_NAME), checkProperties.get(ACTION_PROP_NAME));
                return new AuthorizationDecision(false);
            }
            List<String> parentsUUIDs = parentUUIDGetter.get().getParentsUUID(
                    objectUUIDs.stream().map(u -> u.getValue() == null ? "NULL" : u.toString()).toList());
            resource.setParentObjectUUIDs(parentsUUIDs);
        }

        if (!objectUUIDs.isEmpty()) {
            resource.setObjectUUIDs(objectUUIDs.stream().map(u -> u.getValue() == null ? "NULL" : u.toString()).toList());
        }

        OpaResourceAccessResult result = checkAccess(principal, resource);
        return decideBasedOnOpaResult(request, result, checkProperties);
    }

    private AuthorizationDecision decideBasedOnOpaResult(AuthorizationRequest request, OpaResourceAccessResult result, Map<String, String> checkProperties) {
        if (result.isAuthorized()) {
            log.trace("Access to '%s' has been granted by the following rules [%s].".formatted(request.contextLabel(), String.join(",", result.getAllow())));
            return new AuthorizationDecision(true);
        }
        log.trace("Access to '%s' has been denied.".formatted(request.contextLabel()));
        AuthHelper.setDeniedPermissionResourceAction(checkProperties.get(NAME_PROP_NAME), checkProperties.get(ACTION_PROP_NAME));
        return new AuthorizationDecision(false);
    }

    private OpaResourceAccessResult checkAccess(String principal, OpaRequestedResource resource) {
        try {
            return this.opaClient.checkResourceAccess(OpaPolicy.METHOD.policyName, resource, principal, new OpaRequestDetails(null));
        } catch (Exception e) {
            log.error("An error occurred during the authorization request to the OPA policy '%s'.".formatted(OpaPolicy.METHOD.policyName), e);
            return OpaResourceAccessResult.unauthorized();
        }
    }

    private AuthorizationDecision checkGroupOwnerAssociations(PlatformUserDetails principal, AuthorizationRequest request) {
        Map<String, String> properties = new HashMap<>(request.properties());
        Resource resource;
        ResourceAction resourceAction;
        try {
            resource = Resource.findByCode(properties.get(NAME_PROP_NAME));
            resourceAction = ResourceAction.findByCode(properties.get(ACTION_PROP_NAME));
        } catch (ValidationException e) {
            log.trace("Unsupported resource or action: " + e.getMessage());
            return new AuthorizationDecision(false);
        }

        List<SecuredUUID> objectUUIDs = request.objectUuids();
        boolean hasSecurityFilter = request.hasSecurityFilter();

        Optional<AuthorizationDecision> skipDecision = shouldSkipAuthorizationCheck(objectUUIDs, hasSecurityFilter, resource, resourceAction);
        if (skipDecision.isPresent()) return skipDecision.get();

        // No specific objects requested: grant, since the SecurityFilter will filter out unauthorized objects later.
        if (objectUUIDs.isEmpty()) {
            return new AuthorizationDecision(true);
        }

        if (resource.hasOwner()) {
            Long ownerCount = ownerAssociationRepository.countByOwnerUuidAndResourceAndObjectUuidIn(
                    UUID.fromString(principal.getUserUuid()), resource,
                    objectUUIDs.stream().filter(u -> u.getValue() != null).map(SecuredUUID::getValue).toList());
            if (ownerCount == objectUUIDs.size()) {
                return new AuthorizationDecision(true);
            }
        }

        return evaluateGroupMembersPermissions(principal, request, resource, resourceAction, properties, objectUUIDs)
                .orElseGet(() -> new AuthorizationDecision(false));
    }

    /**
     * Evaluates group-members permissions on the objects' assigned groups; empty when the resource/action combination
     * is not eligible for group-based access.
     */
    private Optional<AuthorizationDecision> evaluateGroupMembersPermissions(PlatformUserDetails principal, AuthorizationRequest request, Resource resource,
                                                                            ResourceAction resourceAction, Map<String, String> properties, List<SecuredUUID> objectUUIDs) {
        if (resource.hasGroups() && (resourceAction == ResourceAction.LIST || resourceAction == ResourceAction.DETAIL)) {
            properties.clear();
            properties.put(NAME_PROP_NAME, Resource.GROUP.getCode());
            properties.put(ACTION_PROP_NAME, ResourceAction.MEMBERS.getCode());

            for (SecuredUUID objectUuid : objectUUIDs) {
                List<String> groupUuids = groupAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid.getValue())
                        .stream().map(g -> g.getGroupUuid().toString()).toList();
                if (groupUuids.isEmpty()) {
                    return Optional.of(new AuthorizationDecision(false));
                }
                OpaRequestedResource opaRequest = new OpaRequestedResource(properties);
                opaRequest.setObjectUUIDs(groupUuids);

                OpaResourceAccessResult result = checkAccess(principal.getRawData(), opaRequest);
                if (!result.isAuthorized()) {
                    log.trace("Access to '%s' object has been denied by missing group member permissions.".formatted(request.contextLabel()));
                    return Optional.of(new AuthorizationDecision(false));
                }
            }
            log.trace("Access to '%s' object has been granted by group member permissions.".formatted(request.contextLabel()));
            return Optional.of(new AuthorizationDecision(true));
        }
        return Optional.empty();
    }

    /**
     * Denies without evaluating associations when the fallback cannot apply: no object UUIDs and no security filter
     * (group/owner associations cannot be evaluated), or the resource has no owner associations and no group
     * associations eligible for the action (groups grant only LIST and DETAIL through group-members permissions).
     * Empty when the group/owner fallback should proceed.
     */
    private static Optional<AuthorizationDecision> shouldSkipAuthorizationCheck(List<SecuredUUID> objectUUIDs, boolean hasSecurityFilter, Resource resource, ResourceAction resourceAction) {
        if ((objectUUIDs.isEmpty() && !hasSecurityFilter) || (!resource.hasOwner() && (!resource.hasGroups() || (resourceAction != ResourceAction.LIST && resourceAction != ResourceAction.DETAIL)))) {
            return Optional.of(new AuthorizationDecision(false));
        }
        return Optional.empty();
    }

    private static Optional<ParentUUIDGetter> instantiateParentUUIDGetter(Optional<Class<ParentUUIDGetter>> parentUuidGetterClass) throws ReflectiveOperationException {
        if (parentUuidGetterClass.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(parentUuidGetterClass.get().getConstructor().newInstance());
    }
}
