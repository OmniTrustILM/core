package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.CzertainlyAuthenticationToken;
import com.otilm.core.security.authn.CzertainlyUserDetails;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.AnonymousPrincipal;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.util.AuthHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class ExternalMethodAuthorizationManager extends AbstractExternalAuthorizationManager<MethodInvocation> {

    protected final Log log = LogFactory.getLog(this.getClass());

    private static final String NAME_PROP_NAME = "name";
    private static final String ACTION_PROP_NAME = "action";
    private static final String PARENT_NAME_PROP_NAME = "parentName";
    private static final String PARENT_ACTION_PROP_NAME = "parentAction";

    private final OpaClient opaClient;

    private final ObjectMapper om;

    private final GroupAssociationRepository groupAssociationRepository;
    private final OwnerAssociationRepository ownerAssociationRepository;

    private final OpaSecuredAnnotationMetadataExtractor metadataExtractor;

    public ExternalMethodAuthorizationManager(@Autowired OpaClient opaClient, @Autowired ObjectMapper om, @Autowired GroupAssociationRepository groupAssociationRepository, @Autowired OwnerAssociationRepository ownerAssociationRepository, @Autowired OpaSecuredAnnotationMetadataExtractor metadataExtractor) {
        this.opaClient = opaClient;
        this.om = om;
        this.groupAssociationRepository = groupAssociationRepository;
        this.ownerAssociationRepository = ownerAssociationRepository;
        this.metadataExtractor = metadataExtractor;
    }

    private List<ExternalAuthorizationConfigAttribute> resolveAttributes(MethodInvocation methodInvocation) {
        ExternalAuthorization staticAnnotation = AnnotationUtils.findAnnotation(methodInvocation.getMethod(), ExternalAuthorization.class);
        if (staticAnnotation != null) {
            return metadataExtractor.extractAttributes(staticAnnotation);
        }

        ExternalAuthorizationDynamic dynamicAnnotation = AnnotationUtils.findAnnotation(methodInvocation.getMethod(), ExternalAuthorizationDynamic.class);
        if (dynamicAnnotation != null) {
            try {
                Resource resolved = SecuredResource.fromArguments(methodInvocation.getArguments()).getResource();
                return metadataExtractor.extractAttributes(dynamicAnnotation, resolved);
            } catch (ValidationException e) {
                log.warn(String.format("Unable to resolve dynamic authorization resource for method '%s'. Voting to deny access.", methodInvocation.getMethod().getName()));
                return null;
            }
        }

        return List.of();
    }

    @Override
    protected AuthorizationDecision checkInternal(CzertainlyAuthenticationToken auth, MethodInvocation methodInvocation) {
        List<ExternalAuthorizationConfigAttribute> attributes = resolveAttributes(methodInvocation);
        if (attributes == null) {
            return new AuthorizationDecision(false);
        }
        AuthorizationDecision result = this.check(auth.getPrincipal().getRawData(), methodInvocation, attributes);
        if (!result.isGranted()) {
            return checkGroupOwnerAssociations(auth.getPrincipal(), methodInvocation, attributes);
        }
        return result;
    }

    @Override
    protected AuthorizationDecision checkInternal(AnonymousAuthenticationToken authenticationToken, MethodInvocation methodInvocation) {
        List<ExternalAuthorizationConfigAttribute> attributes = resolveAttributes(methodInvocation);
        if (attributes == null) {
            return new AuthorizationDecision(false);
        }
        try {
            return this.check(om.writeValueAsString(new AnonymousPrincipal(authenticationToken.getName())), methodInvocation, attributes);
        } catch (JsonProcessingException e) {
            log.error("An error occurred during authorization on method %s. Access will be denied.".formatted(methodInvocation.getMethod().getName()), e);
            return new AuthorizationDecision(false);
        }
    }

    private AuthorizationDecision checkGroupOwnerAssociations(CzertainlyUserDetails principal, MethodInvocation methodInvocation, List<ExternalAuthorizationConfigAttribute> attributes) {
        Map<String, String> properties = attributes
                .stream()
                .filter(this::shouldBeSendToOpa)
                .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::attributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));

        Resource resource;
        ResourceAction resourceAction;
        try {
            resource = Resource.findByCode(properties.get(NAME_PROP_NAME));
            resourceAction = ResourceAction.findByCode(properties.get(ACTION_PROP_NAME));
        } catch (ValidationException e) {
            log.trace("Unsupported resource or action: " + e.getMessage());
            return new AuthorizationDecision(false);
        }

        // UUIDs of objects the operation is executed on
        List<SecuredUUID> objectUUIDs = extractUUIDsFromMethodArguments(methodInvocation);
        boolean hasSecurityFilter = hasSecurityFilterParam(methodInvocation);

        // skip if no object UUIDs provided and it is not listing with security filter - cannot evaluate its group and owner associations
        // skip if no owner associations and no group associations (or in case groups only LIST and DETAIL action is allowed through group members permissions)
        AuthorizationDecision decision = shouldSkipAuthorizationCheck(objectUUIDs, hasSecurityFilter, resource, resourceAction);
        if (decision != null) return decision;

        // does not have objects so grant access since later objects will be filtered out by SecurityFilter
        if (objectUUIDs.isEmpty()) {
            return new AuthorizationDecision(true);
        }

        // evaluate if objects owners equal to principal
        if (resource.hasOwner()) {
            Long ownerCount = ownerAssociationRepository.countByOwnerUuidAndResourceAndObjectUuidIn(UUID.fromString(principal.getUserUuid()), resource, objectUUIDs.stream().filter(u -> u.getValue() != null).map(SecuredUUID::getValue).toList());
            if (ownerCount == objectUUIDs.size()) {
                return new AuthorizationDecision(true);
            }
        }

        // evaluate group members permissions on objects assigned groups
        AuthorizationDecision groupMembersPermissionsDecision = evaluateGroupMembersPermissions(principal, methodInvocation, resource, resourceAction, properties, objectUUIDs);
        if (groupMembersPermissionsDecision != null) return groupMembersPermissionsDecision;

        return new AuthorizationDecision(false);
    }

    private AuthorizationDecision evaluateGroupMembersPermissions(CzertainlyUserDetails principal, MethodInvocation methodInvocation, Resource resource, ResourceAction resourceAction, Map<String, String> properties, List<SecuredUUID> objectUUIDs) {
        if (resource.hasGroups() && (resourceAction == ResourceAction.LIST || resourceAction == ResourceAction.DETAIL)) {
            properties.clear();
            properties.put(NAME_PROP_NAME, Resource.GROUP.getCode());
            properties.put(ACTION_PROP_NAME, ResourceAction.MEMBERS.getCode());

            for (SecuredUUID objectUuid : objectUUIDs) {
                // load groups associations
                List<String> groupUuids = groupAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid.getValue()).stream().map(g -> g.getGroupUuid().toString()).toList();
                if (groupUuids.isEmpty()) {
                    return new AuthorizationDecision(false);
                }
                OpaRequestedResource opaRequest = new OpaRequestedResource(properties);
                opaRequest.setObjectUUIDs(groupUuids);

                OpaResourceAccessResult result = this.checkAccess(principal.getRawData(), opaRequest);
                if (!result.isAuthorized()) {
                    log.trace(String.format("Access to the method '%s' object has been denied by missing group member permissions.", methodInvocation.getMethod().getName()));
                    return new AuthorizationDecision(false);
                }
            }

            log.trace(String.format("Access to the method '%s' object has been granted by group member permissions.", methodInvocation.getMethod().getName()));
            return new AuthorizationDecision(true);
        }
        return null;
    }

    private static AuthorizationDecision shouldSkipAuthorizationCheck(List<SecuredUUID> objectUUIDs, boolean hasSecurityFilter, Resource resource, ResourceAction resourceAction) {
        if ((objectUUIDs.isEmpty() && !hasSecurityFilter) || (!resource.hasOwner() && (!resource.hasGroups() || (resourceAction != ResourceAction.LIST && resourceAction != ResourceAction.DETAIL)))) {
            return new AuthorizationDecision(false);
        }
        return null;
    }

    private AuthorizationDecision check(String principal, MethodInvocation methodInvocation, List<ExternalAuthorizationConfigAttribute> attributes) {

        try {
            Map<String, String> properties = attributes
                    .stream()
                    .filter(this::shouldBeSendToOpa)
                    .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::attributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));

            Optional<ParentUUIDGetter> parentUUIDGetter = getParentUUIDGetter(attributes);
            if (!Resource.NONE.getCode().equals(properties.get(PARENT_NAME_PROP_NAME))) {
                AuthorizationDecision result = checkResource(principal, methodInvocation, properties, parentUUIDGetter, true);
                if (!result.isGranted()) {
                    AuthHelper.setDeniedPermissionResourceAction(properties.get(PARENT_NAME_PROP_NAME), properties.get(PARENT_ACTION_PROP_NAME));
                    return result;
                }
            }

            return checkResource(principal, methodInvocation, properties, parentUUIDGetter, false);
        } catch (Exception e) {
            log.error(String.format("Unable verify access to the method '%s'. Voting to deny access.", methodInvocation.getMethod().getName()), e);
            return new AuthorizationDecision(false);
        }
    }

    private AuthorizationDecision checkResource(String principal, MethodInvocation methodInvocation, Map<String, String> properties, Optional<ParentUUIDGetter> parentUUIDGetter, boolean parentResource) {
        Map<String, String> checkProperties = properties;

        if (parentResource) {
            Map<String, String> parentProperties = properties.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            parentProperties.put(NAME_PROP_NAME, properties.get(PARENT_NAME_PROP_NAME));
            parentProperties.put(ACTION_PROP_NAME, properties.get(PARENT_ACTION_PROP_NAME));
            checkProperties = parentProperties;
        }
        checkProperties.remove(PARENT_NAME_PROP_NAME);
        checkProperties.remove(PARENT_ACTION_PROP_NAME);

        OpaRequestedResource resource = new OpaRequestedResource(checkProperties);

        // UUIDs of objects the operation is executed on
        List<SecuredUUID> objectUUIDs = parentResource ? extractParentUUIDsFromMethodArguments(methodInvocation) : extractUUIDsFromMethodArguments(methodInvocation);

        // Parent UUID Getter not used for now, remove later
        if (!parentResource && parentUUIDGetter.isPresent()) {
            if (objectUUIDs.isEmpty()) {
                log.error("ParentUUIDGetter specified but no object uuids were found. Access to method %s will be denied.".formatted(methodInvocation.getMethod().getName()));
                AuthHelper.setDeniedPermissionResourceAction(checkProperties.get(NAME_PROP_NAME), checkProperties.get(ACTION_PROP_NAME));
                return new AuthorizationDecision(false);
            } else {
                List<String> parentsUUIDs = parentUUIDGetter.get().getParentsUUID(
                        objectUUIDs.stream()
                                .map(u -> u.getValue() == null ? "NULL" : u.toString()).toList());
                resource.setParentObjectUUIDs(parentsUUIDs);
            }

        }

        if (!objectUUIDs.isEmpty()) {
            List<String> uuids = objectUUIDs.stream()
                    .map(u -> u.getValue() == null ? "NULL" : u.toString()).toList();
            resource.setObjectUUIDs(uuids);
        }

        OpaResourceAccessResult result = this.checkAccess(principal, resource);
        return decideBasedOnOpaResult(methodInvocation, result, checkProperties);
    }

    private AuthorizationDecision decideBasedOnOpaResult(MethodInvocation methodInvocation, OpaResourceAccessResult result, Map<String, String> checkProperties) {
        if (result.isAuthorized()) {
            log.trace(
                    String.format(
                            "Access to the method '%s' has been granted by the following rules [%s].",
                            methodInvocation.getMethod().getName(),
                            String.join(",", result.getAllow())
                    )
            );
            return new AuthorizationDecision(true);
        } else {
            log.trace(String.format("Access to the method '%s' has been denied.", methodInvocation.getMethod().getName()));
            AuthHelper.setDeniedPermissionResourceAction(checkProperties.get(NAME_PROP_NAME), checkProperties.get(ACTION_PROP_NAME));
            return new AuthorizationDecision(false);
        }
    }

    @Override
    protected boolean canDecide(Authentication auth, MethodInvocation object) {
        return true;
    }

    protected OpaResourceAccessResult checkAccess(String principal, OpaRequestedResource resource) {
        try {
            return this.opaClient.checkResourceAccess(OpaPolicy.METHOD.policyName, resource, principal, new OpaRequestDetails(null));
        } catch (Exception e) {
            log.error(

                    "An error occurred during the authorization request to the OPA policy '%s'.".formatted(
                            OpaPolicy.METHOD.policyName),
                    e
            );
            return OpaResourceAccessResult.unauthorized();
        }
    }

    private Optional<ParentUUIDGetter> getParentUUIDGetter(List<ExternalAuthorizationConfigAttribute> attributes) throws InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        @SuppressWarnings("unchecked")
        Optional<Class<ParentUUIDGetter>> parentUUIDGetterClass = attributes.stream()
                .filter(att -> {
                    Object value = att.attributeValue();
                    return (value instanceof Class<?> c) &&
                            ParentUUIDGetter.class.isAssignableFrom(c) &&
                            !NoOpParentUUIDGetter.class.isAssignableFrom(c);
                })
                .map(att -> (Class<ParentUUIDGetter>) att.attributeValue())
                .findFirst();

        Optional<ParentUUIDGetter> parentUUIDGetter = Optional.empty();
        if (parentUUIDGetterClass.isPresent()) {
            parentUUIDGetter = Optional.of(parentUUIDGetterClass.get().getConstructor().newInstance());
        }
        return parentUUIDGetter;
    }

    @SuppressWarnings("unchecked")
    private List<SecuredUUID> extractUUIDsFromMethodArguments(MethodInvocation methodInvocation) {
        List<SecuredUUID> uuids = new ArrayList<>();

        Arrays.stream(methodInvocation.getArguments())
                .filter(arg -> arg instanceof SecuredUUID && !(arg instanceof SecuredParentUUID))
                .forEach(arg -> uuids.add((SecuredUUID) arg));

        Arrays.stream(methodInvocation.getArguments())
                .filter(arg -> arg instanceof List<?> l && !l.isEmpty() && l.get(0) instanceof SecuredUUID && !(l.get(0) instanceof SecuredParentUUID))
                .forEach(arg -> uuids.addAll(((List<SecuredUUID>) arg)));

        return uuids;
    }

    @SuppressWarnings("unchecked")
    private List<SecuredUUID> extractParentUUIDsFromMethodArguments(MethodInvocation methodInvocation) {
        List<SecuredUUID> uuids = new ArrayList<>();

        Arrays.stream(methodInvocation.getArguments())
                .filter(SecuredParentUUID.class::isInstance)
                .forEach(arg -> uuids.add((SecuredParentUUID) arg));

        Arrays.stream(methodInvocation.getArguments())
                .filter(arg -> arg instanceof List<?> l && !l.isEmpty() && l.getFirst() instanceof SecuredParentUUID)
                .forEach(arg -> uuids.addAll(((List<SecuredParentUUID>) arg)));

        return uuids;
    }

    private boolean hasSecurityFilterParam(MethodInvocation methodInvocation) {
        return Arrays.stream(methodInvocation.getArguments()).anyMatch(SecurityFilter.class::isInstance);
    }

    private boolean shouldBeSendToOpa(ExternalAuthorizationConfigAttribute att) {
        Object value = att.attributeValue();
        return value.getClass().isPrimitive() ||
                value instanceof String ||
                value instanceof Integer ||
                value instanceof Boolean ||
                value instanceof Float ||
                value instanceof Double;
    }
}
