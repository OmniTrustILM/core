package com.otilm.core.settings;

import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;

/**
 * Immutable pairing of the authentication settings with the generation that produced them. A token-authentication flow
 * captures one snapshot at entry so the identity it resolves and the cache generation it stores under always describe
 * the same settings.
 */
public record AuthenticationSettingsSnapshot(AuthenticationSettingsDto settings, long generation) {
}
