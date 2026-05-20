package com.czertainly.core.security.authz;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The endpoint is open to any authenticated principal. The caller must be authenticated, but no
 * resource-level OPA check is performed via the annotation — either the response is identical for
 * every user (example: {@code EnumService.getPlatformEnums()}), or the method enforces
 * authorization downstream through a {@link SecurityFilter} passed to internal-only operations.
 * <p>
 * Permanent: the no-OPA-check contract for these operations does not change after migration.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AnyPrincipalEndpoint {
}
