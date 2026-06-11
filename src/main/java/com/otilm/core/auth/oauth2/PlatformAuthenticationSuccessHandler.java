package com.otilm.core.auth.oauth2;

import com.otilm.api.model.core.logging.enums.*;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Constants;
import com.otilm.core.util.OAuth2Util;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class PlatformAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(PlatformAuthenticationSuccessHandler.class);

    private OAuth2AuthorizedClientService authorizedClientService;

    private AuditLogInternalService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogInternalService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Autowired
    public void setAuthorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.SESSION);
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) authentication;
        OidcUser oidcUser = (OidcUser) authenticationToken.getPrincipal();

        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(), authentication.getName());
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        OAuth2ProviderSettingsDto providerSettings = authenticationSettings.getOAuth2Providers().get(authenticationToken.getAuthorizedClientRegistrationId());
        if (providerSettings == null) {
            String message = "Unknown OAuth2 Provider with name '%s' for authentication with OAuth2 flow".formatted(authenticationToken.getAuthorizedClientRegistrationId());
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, message, authorizedClient.getAccessToken().getTokenValue());
            throw new PlatformAuthenticationException(message);
        }

        // Get username using configurable claim name from provider settings
        String usernameClaimName = providerSettings.getUsernameClaim();
        if (usernameClaimName == null || usernameClaimName.isEmpty()) {
            usernameClaimName = OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME;
        }
        Object username = oidcUser.getAttribute(usernameClaimName);
        if (username != null) {
            LoggingHelper.putActorInfoWhenNull(null, null, username.toString());
        }
        try {
            OAuth2Util.validateAudiences(authorizedClient.getAccessToken(), providerSettings);
        } catch (PlatformAuthenticationException e) {
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, e.getMessage(), authorizedClient.getAccessToken().getTokenValue());
            throw e;
        }

        try {
            OAuth2Util.getAllClaimsAvailable(providerSettings, authorizedClient.getAccessToken().getTokenValue(), oidcUser.getIdToken());
        } catch (PlatformAuthenticationException e) {
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, e.getMessage(), authorizedClient.getAccessToken().getTokenValue());
            throw new PlatformAuthenticationException(e.getMessage());
        }

        request.getSession().setAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE, authorizedClient.getAccessToken());
        request.getSession().setAttribute(OAuth2Constants.REFRESH_TOKEN_SESSION_ATTRIBUTE, authorizedClient.getRefreshToken());

        String redirectUrl = (String) request.getSession().getAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE);
        request.getSession().removeAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE);
        request.getSession().removeAttribute(OAuth2Constants.SERVLET_CONTEXT_SESSION_ATTRIBUTE);

        if (redirectUrl == null || redirectUrl.isEmpty()) {
            logger.warn("Authentication of user {} via OAuth2 successful, but redirect URL is missing in session. Redirecting to default.", username);
            redirectUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
        }

        try {
            response.sendRedirect(redirectUrl);
        } catch (IOException e) {
            logger.error("Error occurred when sending redirect user {} to {} after authentication via OAuth2. ", username, redirectUrl);
            return;
        }
        logger.debug("Authentication of user {} via OAuth2 successful, redirecting to {}", username, redirectUrl);
        auditLogService.logAuthentication(Operation.LOGIN, OperationResult.SUCCESS, null, authorizedClient.getAccessToken().getTokenValue());
    }
}
