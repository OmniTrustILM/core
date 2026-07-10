package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@Aspect
@EnableAspectJAutoProxy(exposeProxy = true)
public class ObjectFilterAspect {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private static final String NAME = AuthorizationProperties.NAME;
    private static final String ACTION = AuthorizationProperties.ACTION;
    private static final String PARENT_NAME = AuthorizationProperties.PARENT_NAME;
    private static final String PARENT_ACTION = AuthorizationProperties.PARENT_ACTION;

    private final OpaClient opaClient;

    private final OpaSecuredAnnotationMetadataExtractor opaSecuredAnnotationMetadataExtractor;

    public ObjectFilterAspect(@Autowired OpaClient opaClient, @Autowired OpaSecuredAnnotationMetadataExtractor opaSecuredAnnotationMetadataExtractor) {
        this.opaClient = opaClient;
        this.opaSecuredAnnotationMetadataExtractor = opaSecuredAnnotationMetadataExtractor;
    }

    @Around("@annotation(com.otilm.core.security.authz.ExternalAuthorizationDynamic)")
    public Object obtainObjectAccessDataDynamic(ProceedingJoinPoint joinPoint) throws Throwable {
        return filterObjectsAndProceed(joinPoint, "dynamic ", this::createAttributesFromDynamicAnnotation);
    }

    @Around("@annotation(com.otilm.core.security.authz.ExternalAuthorization)")
    public Object obtainObjectAccessData(ProceedingJoinPoint joinPoint) throws Throwable {
        return filterObjectsAndProceed(joinPoint, "", this::createAttributesFromAnnotation);
    }

    /**
     * Locates the {@link SecurityFilter} argument, obtains the OPA attributes via {@code attributeProvider},
     * populates the filter, and proceeds.
     *
     * @param joinPointKind label woven into the trace message when no filter is present (e.g. {@code "dynamic "})
     * @param attributeProvider resolves the OPA config attributes for the advised join point
     */
    private Object filterObjectsAndProceed(ProceedingJoinPoint joinPoint, String joinPointKind,
                                           Function<ProceedingJoinPoint, Collection<ExternalAuthorizationConfigAttribute>> attributeProvider) throws Throwable {
        Object[] arguments = joinPoint.getArgs();
        SecurityFilter secFilter = getSecurityFilter(arguments);

        if (secFilter == null) {
            logger.trace("No ObjectFilter was found, invoking %sjoin point without filter.".formatted(joinPointKind));
            return joinPoint.proceed();
        }

        logger.trace("ObjectFilter has been found. Going to obtain list of allowed objects.");
        Map<String, String> properties = attributeProvider.apply(joinPoint)
                .stream()
                .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::attributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));
        populateSecurityFilter(properties, secFilter);

        return joinPoint.proceed(arguments);
    }

    /**
     * Populates the security filter for the given resource/action (and optional parent), encapsulating the OPA
     * property keys so callers need not assemble the raw property map themselves. Prefer the
     * {@code ExternalAuthorization}/{@code ExternalAuthorizationDynamic} annotations; use this only when the filter
     * must be built outside an authorized method (e.g. listing a related resource's objects).
     *
     * @param resource resource being authorized
     * @param action action being authorized
     * @param parentResource parent resource, or {@code null} when the resource has no parent
     * @param parentAction parent action, or {@code null} when the resource has no parent
     * @param secFilter security filter to populate
     */
    public void populateSecurityFilter(Resource resource, ResourceAction action, Resource parentResource, ResourceAction parentAction, SecurityFilter secFilter) {
        Map<String, String> properties = new HashMap<>();
        properties.put(NAME, resource.getCode());
        properties.put(ACTION, action.getCode());
        properties.put(PARENT_NAME, parentResource != null ? parentResource.getCode() : Resource.NONE.getCode());
        properties.put(PARENT_ACTION, parentAction != null ? parentAction.getCode() : ResourceAction.NONE.getCode());
        populateSecurityFilter(properties, secFilter);
    }

    /**
     * Populates the security filter with the result of OPA object access invocation.
     * Use this method directly only in very specific scenarios, such as when a resource has two parents.
     * Prefer {@code ExternalAuthorization} annotation instead.
     *
     * @param properties mandatory properties: {@code name}, {@code action}, {@code parentName}, {@code parentAction};
     *                   the map must be mutable — this method destructively removes {@code parentName}/{@code parentAction}
     * @param secFilter security filter to populate
     */
    public void populateSecurityFilter(Map<String, String> properties, SecurityFilter secFilter) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof PlatformAuthenticationToken authToken))
            throw new RuntimeException("Unsupported authentication type.");

        if (!properties.get(PARENT_NAME).equals(Resource.NONE.getCode())) {
            SecurityResourceFilter parentResourceFilter = getResourceFilter(authToken, properties, true);
            secFilter.setParentResourceFilter(parentResourceFilter);
        }
        SecurityResourceFilter resourceFilter = getResourceFilter(authToken, properties, false);
        secFilter.setResourceFilter(resourceFilter);

        try {
            Resource resource = Resource.findByCode(properties.get(NAME));
            ResourceAction resourceAction = ResourceAction.findByCode(properties.get(ACTION));

            // if resource has groups and action is list or detail (only allowed through group membership), load user group members permissions
            if (resource.hasGroups() && (resourceAction == ResourceAction.LIST || resourceAction == ResourceAction.DETAIL)) {
                properties.put(NAME, Resource.GROUP.getCode());
                properties.put(ACTION, ResourceAction.MEMBERS.getCode());

                SecurityResourceFilter groupMembersFilter = getResourceFilter(authToken, properties, false);
                secFilter.setGroupMembersFilter(groupMembersFilter);
            }
        } catch (ValidationException e) {
            logger.trace("Unsupported resource or action: " + e.getMessage());
        } catch (Exception e) {
            logger.trace("Cannot load user group members permissions: " + e.getMessage());
        }
    }

    private SecurityResourceFilter getResourceFilter(PlatformAuthenticationToken auth, Map<String, String> properties, boolean parentResource) {
        Map<String, String> voteProperties = properties;
        if (parentResource) {
            Map<String, String> parentProperties = properties.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            parentProperties.put(NAME, properties.get(PARENT_NAME));
            parentProperties.put(ACTION, properties.get(PARENT_ACTION));
            voteProperties = parentProperties;
        }
        voteProperties.remove(PARENT_NAME);
        voteProperties.remove(PARENT_ACTION);

        OpaObjectAccessResult result = obtainObjectAccess(auth, voteProperties);

        logger.trace("User has the following object access rights. %s".formatted(result.toString()));

        SecurityResourceFilter resourceFilter = SecurityResourceFilter.create();
        resourceFilter.setResource(Resource.findByCode(voteProperties.get(NAME)));
        resourceFilter.setResourceAction(ResourceAction.findByCode(voteProperties.get(ACTION)));
        resourceFilter.addAllowedObjects(result.getAllowedObjects());
        resourceFilter.addDeniedObjects(result.getForbiddenObjects());
        resourceFilter.setAreOnlySpecificObjectsAllowed(!result.isActionAllowedForGroupOfObjects());

        return resourceFilter;
    }

    private Collection<ExternalAuthorizationConfigAttribute> createAttributesFromAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        ExternalAuthorization externalAuthorization = method.getAnnotation(ExternalAuthorization.class);

        return opaSecuredAnnotationMetadataExtractor.extractAttributes(externalAuthorization);
    }

    private Collection<ExternalAuthorizationConfigAttribute> createAttributesFromDynamicAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        ExternalAuthorizationDynamic annotation = signature.getMethod().getAnnotation(ExternalAuthorizationDynamic.class);
        // The Spring Security authorization interceptor runs before this aspect and already denies an unresolvable marker, so exactly one marker is guaranteed here.
        Resource resolvedResource = SecuredResource.fromArguments(joinPoint.getArgs()).getResource();

        return opaSecuredAnnotationMetadataExtractor.extractAttributes(annotation, resolvedResource);
    }

    private SecurityFilter getSecurityFilter(Object[] arguments) {
        SecurityFilter filter = null;

        for (Object argument : arguments) {
            if (argument instanceof SecurityFilter securityFilter) {
                filter = securityFilter;
                break;
            }
        }
        return filter;
    }

    private OpaObjectAccessResult obtainObjectAccess(PlatformAuthenticationToken authentication, Map<String, String> properties) {
        OpaRequestedResource resource = new OpaRequestedResource(properties);

        return this.opaClient.checkObjectAccess(OpaPolicy.OBJECTS.policyName, resource, authentication.getPrincipal().getRawData(), new OpaRequestDetails(null));
    }

}
