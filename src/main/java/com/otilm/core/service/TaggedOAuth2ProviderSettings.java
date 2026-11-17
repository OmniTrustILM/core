package com.otilm.core.service;

import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsResponseDto;

/**
 * A provider's settings and the entity tag of the stored row they were read from. Both are null when the provider does
 * not exist.
 */
public record TaggedOAuth2ProviderSettings(OAuth2ProviderSettingsResponseDto settings, String entityTag) {
}
