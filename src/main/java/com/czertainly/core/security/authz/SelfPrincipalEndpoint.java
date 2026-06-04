package com.czertainly.core.security.authz;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The endpoint operates on the authenticated caller's own identity. The caller must be authenticated, but no
 * resource-level check is needed because the subject of the operation is the principal itself (example: {@code AuthExternalService.getAuthProfile()}).
 * <p>
 * Permanent: no resource-level authorization is expected for self-referential operations.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SelfPrincipalEndpoint {
}
