package com.czertainly.core.security.authz;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The protocol stack authenticates the caller — for example ACME (JWK signature) or SCEP/CMP (CMS/PKI message).
 * No resource-level authorization check via {@link ExternalAuthorization} is needed because the protocol itself
 * carries the authentication proof.
 * <p>
 * Permanent: the authentication model for protocol endpoints does not change after migration.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ProtocolEndpoint {
}
