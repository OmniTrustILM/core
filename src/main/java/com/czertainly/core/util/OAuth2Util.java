package com.czertainly.core.util;

import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.settings.SettingsCache;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.text.ParseException;
import java.util.*;

public class OAuth2Util {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Util.class);


    private OAuth2Util() {
        throw new IllegalStateException("Utility class");
    }

    public static void validateAudiences(OAuth2AccessToken accessToken, OAuth2ProviderSettingsDto providerSettings) {

        List<String> clientAudiences = providerSettings.getAudiences();
        List<String> tokenAudiences;
        try {
            tokenAudiences = SignedJWT.parse(accessToken.getTokenValue()).getJWTClaimsSet().getAudience();
        } catch (ParseException e) {
            throw new CzertainlyAuthenticationException("Could not parse JWT Access Token to validate audiences " + accessToken.getTokenValue());
        }

        if (!(clientAudiences == null || clientAudiences.isEmpty() || tokenAudiences != null && tokenAudiences.stream().anyMatch(clientAudiences::contains))) {
            String errorMessage = "User was not authenticated: audiences %s in access token issued by OAuth2 Provider %s do not match any of audiences %s set for the provider in settings. Token: %s".formatted(StringUtils.join(tokenAudiences), providerSettings.getName(), StringUtils.join(clientAudiences), accessToken.getTokenValue());
            throw new CzertainlyAuthenticationException(errorMessage);
        }

    }

    public static void endUserSession(SecurityContext securityContext) {
        if (securityContext != null) {
            if (securityContext.getAuthentication() == null) {
                logger.warn("No authentication found in security context. User session cannot be ended.");
                return;
            }
            OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) securityContext.getAuthentication();
            AuthenticationSettingsDto authenticationSettingsDto = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
            String authorizedClientRegistrationId = authenticationToken.getAuthorizedClientRegistrationId();
            OAuth2ProviderSettingsDto provider = authenticationSettingsDto.getOAuth2Providers().get(authorizedClientRegistrationId);
            if (provider == null) {
                logger.warn("Provider with client ID {} has not been found. User {} will not be logged out on provider side.", authorizedClientRegistrationId, authenticationToken.getName());
                return;
            }
            DefaultOidcUser oidcUser = (DefaultOidcUser) authenticationToken.getPrincipal();
            String idToken = oidcUser.getIdToken().getTokenValue();
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
            String endSessionEndpoint = provider.getLogoutUrl();
            URI uri = UriComponentsBuilder
                    .fromUriString(endSessionEndpoint)
                    .queryParam("id_token_hint", idToken)
                    .build()
                    .toUri();
            try {
                restTemplate.getForEntity(uri, Void.class);
            } catch (Exception e) {
                logger.error("Failed to log out user {} from OAuth2 provider {} at endpoint {}: {}", authenticationToken.getName(), provider.getName(), endSessionEndpoint, e.getMessage(), e);
            }
        }
    }

    private static Map<String, Object> getUserInfo(String userInfoUrl, String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        HttpMethod httpMethod = HttpMethod.GET;
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        URI uri = UriComponentsBuilder
                .fromUriString(userInfoUrl)
                .build()
                .toUri();

        RequestEntity<?> request;
        headers.setBearerAuth(accessToken);
        request = new RequestEntity<>(headers, httpMethod, uri);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(request, new ParameterizedTypeReference<>() {});
        return response.getBody();
    }

    private static Map<String, Object> mergeClaims(Map<String, Object> accessTokenClaims, Map<String,Object> idTokenClaims, Map<String, Object> userInfoClaims) {
        Map<String,Object> mergedClaims = new HashMap<>();

        if (accessTokenClaims != null) mergedClaims.putAll(accessTokenClaims);
        if (userInfoClaims != null) mergedClaims.putAll(userInfoClaims);
        if (idTokenClaims != null) mergedClaims.putAll(idTokenClaims);

        return mergedClaims;
    }

    public static Map<String, Object> getAllClaimsAvailable(OAuth2ProviderSettingsDto providerSettings, String accessTokenValue, OidcIdToken idToken) {
        Map<String, Object> userInfoClaims = null;
        if (providerSettings != null && providerSettings.getUserInfoUrl() != null) {
            try {
                userInfoClaims = getUserInfo(providerSettings.getUserInfoUrl(), accessTokenValue);
            } catch (Exception e) {
                logger.warn("Could not access User Info Endpoint {}: {}", providerSettings.getUserInfoUrl(), e.getMessage());
            }
        }

        Map<String, Object> accessTokenClaims;
        try {
            accessTokenClaims = SignedJWT.parse(accessTokenValue).getJWTClaimsSet().getClaims();
        } catch (ParseException e) {
            String message = "Could not convert access token to JWT and extract claims. Reason: %s Token: %s".formatted(e.getMessage(), accessTokenValue);
            throw new CzertainlyAuthenticationException(message);
        }

        Map<String, Object> claims = mergeClaims(accessTokenClaims, idToken == null ? null : idToken.getClaims(), userInfoClaims);
        // Use configurable username claim name from provider settings, with fallback to default
        String usernameClaimName = providerSettings != null && providerSettings.getUsernameClaim() != null && !providerSettings.getUsernameClaim().isEmpty()
                ? providerSettings.getUsernameClaim()
                : OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME;

        if (!claims.containsKey(usernameClaimName)) {
            String message = "The username claim '%s' could not be retrieved from the Access Token, User Info Endpoint, or ID Token claims for user authenticating with Access Token. Claims %s, Token: %s".formatted(usernameClaimName, StringUtils.join(claims), accessTokenValue);
            throw new CzertainlyAuthenticationException(message);
        }

        return claims;
    }

}
