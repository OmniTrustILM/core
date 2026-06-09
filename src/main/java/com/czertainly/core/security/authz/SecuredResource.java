package com.czertainly.core.security.authz;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;

/**
 * Marks a method argument as the {@link Resource} the caller must be authorized against, for methods annotated
 * with {@link ExternalAuthorizationDynamic}. Analogous to {@link SecuredUUID}: the authorization interceptor and
 * {@link ObjectFilterAspect} resolve the auth subject by this marker type, so a bare {@link Resource} argument
 * (data, e.g. a dispatch discriminator) is never mistaken for the protected resource.
 */
@Getter
public class SecuredResource {

    private final Resource resource;

    protected SecuredResource(Resource resource) {
        this.resource = resource;
    }

    public static SecuredResource fromResource(Resource resource) {
        if (resource == null) {
            return null;
        }
        return new SecuredResource(resource);
    }

    /**
     * Resolves the single {@link SecuredResource} argument from a method invocation's arguments. Zero or more
     * than one is a programming error and is rejected, so the caller is denied rather than silently mis-authorized.
     */
    public static SecuredResource fromArguments(Object[] arguments) {
        List<SecuredResource> resources = Arrays.stream(arguments)
                .filter(SecuredResource.class::isInstance)
                .map(SecuredResource.class::cast)
                .toList();
        if (resources.size() != 1) {
            throw new ValidationException(ValidationError.create(
                    "Cannot resolve dynamic authorization resource: expected exactly one SecuredResource argument but found "
                            + resources.size()));
        }
        return resources.getFirst();
    }

    @Override
    public String toString() {
        return resource == null ? "SecuredResource[null]" : resource.getCode();
    }
}
