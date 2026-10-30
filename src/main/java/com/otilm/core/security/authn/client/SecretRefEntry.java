package com.otilm.core.security.authn.client;

import java.util.UUID;

/**
 * Immutable cache value for {@code CREDENTIAL_VERIFICATION_CACHE}.
 */
public record SecretRefEntry(UUID secretUuid, UUID mappedUserUuid) {
}
