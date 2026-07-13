package com.otilm.core.service.v2;

import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;

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

    /**
     * Resolves the OAuth2 provider settings for a login attempt. When the provider is unknown,
     * writes a LOGIN/FAILURE audit record (with the session access token as auth data, if any)
     * and throws.
     *
     * @throws PlatformAuthenticationException when no provider with the given name is configured
     */
    OAuth2ProviderSettingsDto resolveProviderOrThrow(String providerName, String sessionAccessToken);

    /**
     * Validates and normalizes the redirect URL for the v2 login flow. When missing or invalid,
     * writes a LOGIN/FAILURE audit record and throws.
     *
     * @throws PlatformAuthenticationException when the redirect URL is missing or invalid
     */
    String validateRedirectOrThrow(String redirectUrl);
}
