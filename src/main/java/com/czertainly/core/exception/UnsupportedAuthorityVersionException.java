package com.czertainly.core.exception;

/**
 * Thrown by AuthorityProviderAdapterFactory when no adapter is registered for the
 * authority's connector interface version. Defensive — v1 authorities should never
 * reach the factory per the structural separation between legacy v1 service and the
 * v2/v3 adapter-based service.
 */
public class UnsupportedAuthorityVersionException extends RuntimeException {
    public UnsupportedAuthorityVersionException(String message) { super(message); }
}
