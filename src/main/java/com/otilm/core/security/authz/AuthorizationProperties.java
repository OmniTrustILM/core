package com.otilm.core.security.authz;

/**
 * Property-map keys shared by the OPA authorization request protocol. The builders that write these keys
 * ({@link AuthorizationRequest#forDirectCheck}) and the readers that consume them
 * ({@link ExternalAuthorizationCore}, {@link ObjectFilterAspect}) must agree on the exact strings; keeping
 * them here prevents a rename in one place from silently desyncing the OPA request (which would fail-closed
 * and deny legitimate calls).
 */
final class AuthorizationProperties {

    static final String NAME = "name";
    static final String ACTION = "action";
    static final String PARENT_NAME = "parentName";
    static final String PARENT_ACTION = "parentAction";

    private AuthorizationProperties() {
    }
}
