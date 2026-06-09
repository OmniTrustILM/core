package com.czertainly.core.service.impl;

import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.czertainly.core.service.v2.OAuth2LoginService;
import com.czertainly.core.settings.SettingsCache;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.List;

@Service
@Transactional
public class OAuth2LoginServiceImpl implements OAuth2LoginService {

    @Override
    public boolean isOAuth2ProviderValid(OAuth2ProviderSettingsDto settingsDto) {
        return (settingsDto.getClientId() != null) &&
                (settingsDto.getClientSecret() != null) &&
                (settingsDto.getAuthorizationUrl() != null) &&
                (settingsDto.getTokenUrl() != null) &&
                (settingsDto.getJwkSetUrl() != null || settingsDto.getJwkSet() != null) &&
                (settingsDto.getLogoutUrl() != null) &&
                (settingsDto.getPostLogoutUrl() != null);
    }

    @Override
    public List<OAuth2ProviderSettingsDto> getValidOAuth2Providers() {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        if (authenticationSettings.getOAuth2Providers() == null) {
            return List.of();
        }
        return authenticationSettings.getOAuth2Providers().values().stream()
                .filter(this::isOAuth2ProviderValid)
                .toList();
    }

    @Override
    public OAuth2ProviderSettingsDto getOAuth2ProviderSettings(String providerName) {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        if (authenticationSettings.getOAuth2Providers() == null) {
            return null;
        }
        return authenticationSettings.getOAuth2Providers().get(providerName);
    }

    @Override
    public String validateAndNormalizeRedirect(String redirectUrl) {
        if (redirectUrl == null || redirectUrl.isEmpty()) {
            return null;
        }

        // Must be a relative path (starts with /) and not protocol-relative (not starting with //)
        if (!redirectUrl.startsWith("/") || redirectUrl.startsWith("//")) {
            return null;
        }

        // Basic normalization to remove host/scheme if any (though startsWith("/") already helps)
        try {
            URI uri = URI.create(redirectUrl);
            if (uri.isAbsolute() || uri.getHost() != null) {
                return null;
            }
            return uri.getPath() + (uri.getQuery() != null ? "?" + uri.getQuery() : "") + (uri.getFragment() != null ? "#" + uri.getFragment() : "");
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
