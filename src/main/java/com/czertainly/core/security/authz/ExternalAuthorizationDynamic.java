package com.czertainly.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that a method requires an OPA authorization check whose target {@link Resource} is not known at
 * compile time but is supplied as a method argument. Use this instead of {@link ExternalAuthorization} when the
 * protected resource is a runtime parameter.
 * <p>
 * The protected resource is resolved from the single {@link SecuredResource} argument present in the method
 * invocation (mirroring how {@link SecuredUUID} arguments are resolved). Object UUIDs, when applicable, are
 * resolved exactly as for {@link ExternalAuthorization}: from {@link SecuredUUID} arguments (object-level
 * checks) or, for listings, a {@link SecurityFilter} argument populated by {@link ObjectFilterAspect}.
 * <p>
 * Place this annotation on the implementation class method (not the interface) so Spring AOP can intercept it.
 *
 * <pre>{@code
 * @ExternalAuthorizationDynamic(action = ResourceAction.LIST)
 * public List<NameAndUuidDto> getResourceObjects(SecuredResource resource, SecurityFilter filter, ...) { ... }
 * }</pre>
 */
@Documented
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ExternalAuthorizationDynamic {

    /** The action the caller must be permitted to perform on the runtime-resolved resource. */
    ResourceAction action() default ResourceAction.NONE;

    /** Optional parent resource checked before the main resource. Default {@link Resource#NONE}. */
    Resource parentResource() default Resource.NONE;

    /** Action on {@link #parentResource()}; ignored when the parent is {@link Resource#NONE}. */
    ResourceAction parentAction() default ResourceAction.NONE;
}
