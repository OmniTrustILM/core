package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class ExternalMethodAuthorizationManager extends AbstractExternalAuthorizationManager<MethodInvocation> {

    protected final Log log = LogFactory.getLog(this.getClass());

    private final OpaSecuredAnnotationMetadataExtractor metadataExtractor;
    private final ExternalAuthorizationCore core;

    public ExternalMethodAuthorizationManager(OpaSecuredAnnotationMetadataExtractor metadataExtractor, ExternalAuthorizationCore core) {
        this.metadataExtractor = metadataExtractor;
        this.core = core;
    }

    @Override
    protected AuthorizationDecision checkInternal(PlatformAuthenticationToken auth, MethodInvocation methodInvocation) {
        return check(auth, methodInvocation);
    }

    @Override
    protected AuthorizationDecision checkInternal(AnonymousAuthenticationToken authenticationToken, MethodInvocation methodInvocation) {
        return check(authenticationToken, methodInvocation);
    }

    private AuthorizationDecision check(Authentication authentication, MethodInvocation methodInvocation) {
        AuthorizationRequest request = resolveRequest(methodInvocation);
        if (request == null) {
            return new AuthorizationDecision(false);
        }
        return core.decide(authentication, request);
    }

    private AuthorizationRequest resolveRequest(MethodInvocation methodInvocation) {
        List<ExternalAuthorizationConfigAttribute> attributes = resolveAttributes(methodInvocation);
        if (attributes == null) {
            return null;
        }
        Map<String, String> properties = attributes.stream()
                .filter(this::shouldBeSendToOpa)
                .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::attributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));
        return new AuthorizationRequest(
                properties,
                extractUUIDsFromMethodArguments(methodInvocation),
                extractParentUUIDsFromMethodArguments(methodInvocation),
                hasSecurityFilterParam(methodInvocation),
                extractParentUUIDGetterClass(attributes),
                methodInvocation.getMethod().getName());
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
                log.warn("Unable to resolve dynamic authorization resource for method '%s'. Voting to deny access.".formatted(methodInvocation.getMethod().getName()));
                return null;
            }
        }
        return List.of();
    }

    @Override
    protected boolean canDecide(Authentication auth, MethodInvocation object) {
        return true;
    }

    @SuppressWarnings("unchecked")
    private static Optional<Class<ParentUUIDGetter>> extractParentUUIDGetterClass(List<ExternalAuthorizationConfigAttribute> attributes) {
        return attributes.stream()
                .filter(att -> {
                    Object value = att.attributeValue();
                    return (value instanceof Class<?> c)
                            && ParentUUIDGetter.class.isAssignableFrom(c)
                            && !NoOpParentUUIDGetter.class.isAssignableFrom(c);
                })
                .map(att -> (Class<ParentUUIDGetter>) att.attributeValue())
                .findFirst();
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
