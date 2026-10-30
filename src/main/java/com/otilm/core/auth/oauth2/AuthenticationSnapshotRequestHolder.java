package com.otilm.core.auth.oauth2;

import com.otilm.core.settings.AuthenticationSettingsSnapshot;

/**
 * Carries the authentication-settings snapshot that {@link PlatformJwtDecoder} validated a token against to the
 * components that resolve the identity from that token later in the same request.
 *
 * <p>
 * Token validation (JWK set, audiences, clock skew) and identity resolution (username claim, cache generation) happen
 * in two separate components. Reading the snapshot twice would let a concurrent settings update slip between them,
 * validating under one provider configuration and resolving the identity under another. The decoder therefore publishes
 * the snapshot it used, and the identity resolvers consume it.
 *
 * <p>
 * The value is bound to the request-handling thread, which is pooled, so it must never outlive the request that
 * published it: {@link AuthenticationSnapshotRequestFilter} clears it around every request.
 */
public final class AuthenticationSnapshotRequestHolder {

    private static final ThreadLocal<AuthenticationSettingsSnapshot> CURRENT = new ThreadLocal<>();

    private AuthenticationSnapshotRequestHolder() {
        throw new IllegalStateException("Utility class");
    }

    public static void set(AuthenticationSettingsSnapshot snapshot) {
        CURRENT.set(snapshot);
    }

    /** Returns the snapshot published for the current thread, or {@code null} when nothing was published. */
    public static AuthenticationSettingsSnapshot get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
