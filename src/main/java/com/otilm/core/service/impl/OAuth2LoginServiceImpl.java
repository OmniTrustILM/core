package com.otilm.core.service.impl;

import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authz.UnauthenticatedEndpoint;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.v2.OAuth2LoginExternalService;
import com.otilm.core.settings.SettingsCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;

@Service
public class OAuth2LoginServiceImpl implements OAuth2LoginExternalService {

    private AuditLogInternalService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogInternalService auditLogService) {
        this.auditLogService = auditLogService;
    }

    private boolean isOAuth2ProviderValid(OAuth2ProviderSettingsDto settingsDto) {
        return (settingsDto.getClientId() != null) &&
                (settingsDto.getClientSecret() != null) &&
                (settingsDto.getAuthorizationUrl() != null) &&
                (settingsDto.getTokenUrl() != null) &&
                (settingsDto.getJwkSetUrl() != null || settingsDto.getJwkSet() != null) &&
                (settingsDto.getLogoutUrl() != null) &&
                (settingsDto.getPostLogoutUrl() != null);
    }

    @Override
    @UnauthenticatedEndpoint
    public List<OAuth2ProviderSettingsDto> getValidOAuth2Providers() {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        if (authenticationSettings.getOAuth2Providers() == null) {
            return List.of();
        }
        return authenticationSettings.getOAuth2Providers().values().stream()
                .filter(this::isOAuth2ProviderValid)
                .toList();
    }

    private OAuth2ProviderSettingsDto getOAuth2ProviderSettings(String providerName) {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        if (authenticationSettings.getOAuth2Providers() == null) {
            return null;
        }
        return authenticationSettings.getOAuth2Providers().get(providerName);
    }

    @Override
    @UnauthenticatedEndpoint
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

    @Override
    @UnauthenticatedEndpoint
    public OAuth2ProviderSettingsDto resolveProviderOrThrow(String providerName, String sessionAccessToken) {
        OAuth2ProviderSettingsDto providerSettings = getOAuth2ProviderSettings(providerName);
        if (providerSettings == null) {
            String message = "Unknown OAuth2 Provider with name '%s' for authentication with OAuth2 flow".formatted(providerName);
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, message, sessionAccessToken);
            throw new PlatformAuthenticationException(message);
        }
        return providerSettings;
    }

    @Override
    @UnauthenticatedEndpoint
    public String validateRedirectOrThrow(String redirectUrl) {
        String validatedRedirectUrl = validateAndNormalizeRedirect(redirectUrl);
        if (validatedRedirectUrl == null) {
            String errorMessage = "Missing or invalid redirect URL. Please start the login from the beginning.";
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, errorMessage, null);
            throw new PlatformAuthenticationException(errorMessage);
        }
        return validatedRedirectUrl;
    }
}
