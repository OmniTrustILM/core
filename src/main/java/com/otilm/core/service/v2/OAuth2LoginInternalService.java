package com.otilm.core.service.v2;

import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;

public interface OAuth2LoginInternalService {

    /**
     * Checks if the OAuth2 provider is valid and has all required settings.
     * @param settingsDto OAuth2 provider settings
     * @return true if the provider is valid
     */
    boolean isOAuth2ProviderValid(OAuth2ProviderSettingsDto settingsDto);

    /**
     * Get OAuth2 provider settings by name
     * @param providerName OAuth2 provider name
     * @return OAuth2 provider settings or null if not found
     */
    OAuth2ProviderSettingsDto getOAuth2ProviderSettings(String providerName);
}
