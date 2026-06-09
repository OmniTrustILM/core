package com.otilm.core.util;

import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.v2.OAuth2LoginService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public final class OAuth2LoginFlowHelper {

    private OAuth2LoginFlowHelper() {
        // Utility class.
    }

    public static OAuth2ProviderSettingsDto resolveProviderOrThrow(String provider, HttpServletRequest request, OAuth2LoginService oauth2LoginService, AuditLogInternalService auditLogService) {
        OAuth2ProviderSettingsDto providerSettings = oauth2LoginService.getOAuth2ProviderSettings(provider);
        if (providerSettings == null) {
            String accessToken;
            try {
                OAuth2AccessToken oauth2AccessToken = (OAuth2AccessToken) request.getSession(false).getAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE);
                accessToken = oauth2AccessToken.getTokenValue();
            } catch (NullPointerException e) {
                accessToken = null;
            }

            String message = "Unknown OAuth2 Provider with name '%s' for authentication with OAuth2 flow".formatted(provider);
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, message, accessToken);
            throw new PlatformAuthenticationException(message);
        }
        return providerSettings;
    }
}
