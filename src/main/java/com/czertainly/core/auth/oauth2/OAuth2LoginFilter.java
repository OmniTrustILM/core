package com.czertainly.core.auth.oauth2;

import com.czertainly.api.model.core.logging.enums.*;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authn.CzertainlyUserDetails;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import com.czertainly.core.service.AuditLogService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.OAuth2Constants;
import com.czertainly.core.util.OAuth2Util;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Component
public class OAuth2LoginFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2LoginFilter.class);

    private CzertainlyAuthenticationClient authenticationClient;
    private CzertainlyClientRegistrationRepository clientRegistrationRepository;
    private OAuth2AuthorizedClientProvider authorizedClientProvider;

    private AuditLogService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Autowired
    public void setAuthorizedClientProvider(OAuth2AuthorizedClientProvider authorizedClientProvider) {
        this.authorizedClientProvider = authorizedClientProvider;
    }

    @Autowired
    public void setAuthenticationClient(CzertainlyAuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    @Autowired
    public void setClientRegistrationRepository(CzertainlyClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.SESSION);

            OAuth2AccessToken oauth2AccessToken = (OAuth2AccessToken) request.getSession().getAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE);
            OAuth2ProviderSettingsDto providerSettings = getProviderSettings(oauthToken.getAuthorizedClientRegistrationId(), request.getSession(), oauth2AccessToken);

            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(oauthToken.getAuthorizedClientRegistrationId());
            OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, oauthToken.getName(), oauth2AccessToken, (OAuth2RefreshToken) request.getSession().getAttribute(OAuth2Constants.REFRESH_TOKEN_SESSION_ATTRIBUTE));

            Instant now = Instant.now();
            Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
            int skew = providerSettings.getSkew();

            // If the access token is expired, try to refresh it
            if (expiresAt != null && expiresAt.isBefore(now.plus(skew, ChronoUnit.SECONDS))) {
                try {
                    authorizedClient = refreshToken(oauthToken, authorizedClient, request.getSession(), clientRegistration, providerSettings);
                    oauth2AccessToken = authorizedClient.getAccessToken();
                } catch (ClientAuthorizationException | CzertainlyAuthenticationException e) {
                    request.getSession().invalidate();
                    String message = ("Could not refresh token: %s for access token : %s").formatted(e.getMessage(), oauth2AccessToken.getTokenValue());
                    auditLogService.logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, message, oauth2AccessToken.getTokenValue());
                    logger.error(e.getMessage());
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
                    return;
                }
                try {
                    OAuth2Util.validateAudiences(authorizedClient.getAccessToken(), providerSettings);
                } catch (CzertainlyAuthenticationException e) {
                    request.getSession().invalidate();
                    auditLogService.logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, e.getMessage(), oauth2AccessToken.getTokenValue());
                    logger.error(e.getMessage());
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
                    return;
                }
            }
            Map<String, Object> claims;
            try {
                OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
                claims = OAuth2Util.getAllClaimsAvailable(providerSettings, oauth2AccessToken.getTokenValue(), oidcUser.getIdToken());
            } catch (CzertainlyAuthenticationException e) {
                request.getSession().invalidate();
                auditLogService.logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, e.getMessage(), authorizedClient.getAccessToken().getTokenValue());
                logger.error(e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
                return;
            }
            authenticate(request, claims, clientRegistration);
        }

        try {
            filterChain.doFilter(request, response);
        } catch (IOException | ServletException e) {
            request.getSession().invalidate();
            LOGGER.error("Error when proceeding with OAuth2Login filter: {}", e.getMessage());
        }
    }

    private void authenticate(HttpServletRequest request, Map<String, Object> claims, ClientRegistration clientRegistration) {
        AuthenticationInfo authInfo;
        try {
            authInfo = authenticationClient.authenticate(AuthMethod.TOKEN, claims, false);
            CzertainlyAuthenticationToken authenticationToken = new CzertainlyAuthenticationToken(new CzertainlyUserDetails(authInfo));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            LOGGER.debug("Session of user '{}' logged using OAuth2 Provider '{}' has been successfully validated.", authenticationToken.getPrincipal().getUsername(), clientRegistration.getRegistrationId());
        } catch (AuthenticationException e) {
            // invalidate session when authentication fails
            request.getSession().invalidate();
            SecurityContextHolder.clearContext();
            if (e instanceof CzertainlyAuthenticationException) {
                LOGGER.warn("Authentication request for '{}' failed: {}", request.getRequestURI(), e.getMessage());
            } else {
                throw e;
            }
        }
    }

    private OAuth2AuthorizedClient refreshToken(OAuth2AuthenticationToken oauthToken, OAuth2AuthorizedClient authorizedClient, HttpSession session, ClientRegistration clientRegistration, OAuth2ProviderSettingsDto providerSettings) {
        if (authorizedClient.getRefreshToken() != null) {
            // Refresh the token
            OAuth2AuthorizationContext context = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
                    .principal(oauthToken)
                    .attribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME, clientRegistration.getScopes().toArray(new String[0]))
                    .build();

            authorizedClient = authorizedClientProvider.authorize(context);

            // Save the refreshed authorized client with refreshed access token
            if (authorizedClient != null) {

                // Use configurable username claim name from provider settings, with fallback to default
                String usernameClaimName = providerSettings.getUsernameClaim() != null && !providerSettings.getUsernameClaim().isEmpty()
                        ? providerSettings.getUsernameClaim()
                        : OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME;

                Object usernameClaim = oauthToken.getPrincipal().getAttribute(usernameClaimName);
                if (usernameClaim == null) {
                    throw new CzertainlyAuthenticationException("Missing username claim '%s' in token attributes.".formatted(usernameClaimName));
                }

                LOGGER.debug("OAuth2 Access Token has been refreshed for user {}.", usernameClaim);
                session.setAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE, authorizedClient.getAccessToken());
                session.setAttribute(OAuth2Constants.REFRESH_TOKEN_SESSION_ATTRIBUTE, authorizedClient.getRefreshToken());
            } else {
                throw new CzertainlyAuthenticationException("Failed to refresh the access token.");
            }
        } else {
            throw new CzertainlyAuthenticationException("Refresh token is not available ");
        }
        return authorizedClient;
    }

    private OAuth2ProviderSettingsDto getProviderSettings(String clientRegistrationId, HttpSession session, OAuth2AccessToken oauth2AccessToken) {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        OAuth2ProviderSettingsDto providerSettings = authenticationSettings.getOAuth2Providers().get(clientRegistrationId);
        if (providerSettings == null) {
            session.invalidate();
            String message = "Unknown OAuth2 Provider with name '%s' for authentication with OAuth2 flow".formatted(clientRegistrationId);
            auditLogService.logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, message, oauth2AccessToken.getTokenValue());
            throw new CzertainlyAuthenticationException(message);
        }
        return providerSettings;
    }

}

