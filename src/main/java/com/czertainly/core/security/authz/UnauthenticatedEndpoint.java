package com.czertainly.core.security.authz;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * No Spring Security principal is expected for this endpoint. Access is controlled by deployment topology or
 * transport-level identity — for example the separate {@code local} API surface, or mTLS-authenticated connector self-registration.
 * <p>
 * Permanent: the no-principal contract for these operations does not change after migration.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface UnauthenticatedEndpoint {
}
