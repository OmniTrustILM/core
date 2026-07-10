package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares the {@link Resource}/{@link ResourceAction} pair that a method authorizes <b>programmatically</b> —
 * by calling {@link AuthorizationEnforcer#enforce} in its body — instead of through the declarative
 * {@link ExternalAuthorization} AOP interceptor.
 * <p>
 * This annotation performs no enforcement itself; enforcement is the {@code enforce(...)} call in the method
 * body. Its purpose is registration: {@code ContextRefreshListener} scans authorization annotations at startup
 * to build the resource/action catalogue that is pushed wholesale to the auth service, and the auth service
 * <b>deletes any action absent from that push, together with all permissions granted on it</b>. A method that
 * enforces only imperatively is invisible to the scan, so it must carry this annotation to keep its action
 * registered.
 * <p>
 * Use it when the check cannot run at method entry — typically because the object UUID only becomes known
 * after a lookup inside the method (e.g. name-to-UUID resolution). Keep the declared pair in sync with the
 * {@code enforce(...)} call: the annotation is the source of truth for the auth-service sync, the call is the
 * source of truth for enforcement.
 *
 * <pre>{@code
 * @ExternalAuthorizationProgrammatic(resource = Resource.TSP_PROFILE, action = ResourceAction.TIMESTAMP)
 * public TspResponse processTspRequestForTspProfile(String tspProfileName, TspRequest request) {
 *     TspProfileModel tspProfile = tspProfileService.getTspProfile(tspProfileName);
 *     authorizationEnforcer.enforce(Resource.TSP_PROFILE, ResourceAction.TIMESTAMP,
 *             SecuredUUID.fromUUID(tspProfile.uuid()));
 *     ...
 * }
 * }</pre>
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ExternalAuthorizationProgrammatic {

    /** The resource type the method's programmatic check targets. */
    Resource resource();

    /** The action the method's programmatic check targets on {@link #resource()}. */
    ResourceAction action() default ResourceAction.NONE;

    /**
     * The parent resource the method's programmatic check targets before {@link #resource()}, when the check
     * is parent-scoped. Leave at {@link Resource#NONE} (the default) when there is no parent check.
     */
    Resource parentResource() default Resource.NONE;

    /** The action on {@link #parentResource()}; ignored when the parent is {@link Resource#NONE}. */
    ResourceAction parentAction() default ResourceAction.NONE;
}
