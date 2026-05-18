package com.czertainly.core.security.authz;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.model.auth.ResourceAction;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that a method on an {@code *Service} implementation requires an OPA authorization check before
 * it may execute. Spring Security intercepts the call and consults the OPA policy {@code method} with the caller's
 * identity, the target {@link #resource()}, and the requested {@link #action()}.
 * <p>
 * Object UUIDs for the authorization query are resolved automatically from method parameters of type
 * {@link SecuredUUID} (excluding {@link SecuredParentUUID}). For list-style operations the method may instead
 * accept a {@link SecurityFilter} parameter; in that case OPA receives no object UUIDs and the result set is
 * filtered after the call.
 * <p>
 * When {@link #parentResource()} is set, OPA is first queried for the parent resource (using
 * {@link SecuredParentUUID} method parameters as the object UUIDs), and the main resource is checked only if the
 * parent check passes.
 * <p>
 * Place this annotation on the implementation class method, not on the interface, to ensure Spring AOP can
 * intercept it through the CGLIB proxy.
 *
 * <h3>Simple example</h3>
 * <pre>{@code
 * @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.LIST)
 * public List<RoleDto> listRoles(SecurityFilter filter) { ... }
 * }</pre>
 *
 * <h3>Nested-resource example (parent checked first)</h3>
 * <pre>{@code
 * @ExternalAuthorization(
 *     resource = Resource.LOCATION, action = ResourceAction.CREATE,
 *     parentResource = Resource.ENTITY, parentAction = ResourceAction.DETAIL)
 * public LocationDto createLocation(SecuredParentUUID entityUuid, ...) { ... }
 * }</pre>
 */
@Documented
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ExternalAuthorization {

    /** The resource type the caller must have access to. */
    Resource resource();

    /** The action the caller must be permitted to perform on {@link #resource()}. */
    ResourceAction action() default ResourceAction.NONE;

    /**
     * The parent resource type to check before {@link #resource()}.
     * Leave at {@link Resource#NONE} (the default) when the resource has no authorization-relevant parent.
     * Parent object UUIDs are resolved from {@link SecuredParentUUID} method parameters.
     */
    Resource parentResource() default Resource.NONE;

    /**
     * The action the caller must be permitted to perform on {@link #parentResource()}.
     * Ignored when {@link #parentResource()} is {@link Resource#NONE}.
     */
    ResourceAction parentAction() default ResourceAction.NONE;

    /**
     * @deprecated Do not use, will be removed in future releases.
     */
    @Deprecated
    Class<? extends ParentUUIDGetter> parentObjectUUIDGetter() default NoOpParentUUIDGetter.class;
}
