package com.czertainly.core.security.authz;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Migration marker: this method was moved to an {@code *ExternalService} interface because a controller calls it,
 * but its correct authorization posture has not yet been determined.
 * <p>
 * Must be replaced in a follow-up PR with one of the five permanent annotations
 * ({@link ExternalAuthorization}, {@link ProtocolEndpoint}, {@link SelfPrincipalEndpoint},
 * {@link AnyPrincipalEndpoint}, {@link UnauthenticatedEndpoint}), or the method must be refactored back to internal-only.
 * <p>
 * The outstanding violations are recorded in src/test/resources/archunit_store.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ExternalAuthorizationMissing {
}
