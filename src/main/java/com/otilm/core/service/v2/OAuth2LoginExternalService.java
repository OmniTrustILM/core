package com.otilm.core.service.v2;

import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;

import java.util.List;

public interface OAuth2LoginExternalService {

    /**
     * Get a list of all valid OAuth2 providers.
     * @return list of valid OAuth2 providers
     */
    List<OAuth2ProviderSettingsDto> getValidOAuth2Providers();

    /**
     * Validate and normalize redirect URL to be a relative path.
     * @param redirectUrl Redirect URL to validate
     * @return Normalized redirect URL or null if invalid
     */
    String validateAndNormalizeRedirect(String redirectUrl);
}
