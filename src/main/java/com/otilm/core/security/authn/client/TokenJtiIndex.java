package com.otilm.core.security.authn.client;

import org.springframework.stereotype.Component;

/**
 * Secondary index of the token-cache keys cached for each user. Each key is the settings-generation, issuer and
 * {@code jti} composite built by {@link PlatformAuthenticationCache}; this index treats it as an opaque string.
 */
@Component
public class TokenJtiIndex extends UserKeyIndex {
}
