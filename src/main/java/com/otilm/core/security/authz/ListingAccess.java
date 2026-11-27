package com.otilm.core.security.authz;

/** How a caller passed {@link AuthorizationEnforcer#enforceListing}. */
public enum ListingAccess {

    /** Through a resource-level list grant, so every object of the resource may be listed. */
    RESOURCE_WIDE,

    /**
     * Through the listings of the caller's profile alone, so only some objects of the resource may be listed and data
     * read across all of them must not be disclosed.
     */
    RESTRICTED
}
