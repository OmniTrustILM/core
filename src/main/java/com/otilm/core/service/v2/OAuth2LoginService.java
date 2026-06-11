package com.otilm.core.service.v2;

import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;

import java.util.List;

public interface OAuth2LoginService {

    /**
     * Checks if the OAuth2 provider is valid and has all required settings.
     * @param settingsDto OAuth2 provider settings
     * @return true if the provider is valid
     */
    boolean isOAuth2ProviderValid(OAuth2ProviderSettingsDto settingsDto);

    /**
     * Get a list of all valid OAuth2 providers.
     * @return list of valid OAuth2 providers
     */
    List<OAuth2ProviderSettingsDto> getValidOAuth2Providers();

    /**
     * Get OAuth2 provider settings by name
     * @param providerName OAuth2 provider name
     * @return OAuth2 provider settings or null if not found
     */
    OAuth2ProviderSettingsDto getOAuth2ProviderSettings(String providerName);

    /**
     * Validate and normalize redirect URL to be a relative path.
     * @param redirectUrl Redirect URL to validate
     * @return Normalized redirect URL or null if invalid
     */
    String validateAndNormalizeRedirect(String redirectUrl);
}
