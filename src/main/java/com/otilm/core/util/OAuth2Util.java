package com.otilm.core.util;

import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.config.http.PlatformHttpClients;
import com.otilm.core.logging.LogRedaction;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.settings.SettingsCache;
import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuth2Util {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Util.class);

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(10);

    /**
     * Shared client for the provider-side OAuth2 endpoints (end-session, userinfo). {@link RestClient} is immutable and
     * thread-safe, so a single instance serves all calls.
     */
    private static final RestClient restClient = buildRestClient();

    /**
     * Pool sizing, cookie handling, proxy wiring and retry policy come from {@link PlatformHttpClients}; what is
     * specific here is how the provider's responses are mapped.
     */
    private static RestClient buildRestClient() {
        HttpClientSettings settings = HttpClientSettings
                .defaults()
                .withConnectTimeout(CONNECT_TIMEOUT)
                .withReadTimeout(READ_TIMEOUT);

        return RestClient
                .builder()
                .requestFactory(PlatformHttpClients.requestFactoryBuilder().build(settings))
                .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
                .defaultStatusHandler(HttpStatusCode::is3xxRedirection, OAuth2Util::rejectUnfollowedRedirect)
                .build();
    }

    /**
     * A redirect reaching the caller means Apache declined to follow it — it refuses cross-authority redirects on
     * requests carrying an {@code Authorization} header. Left alone, {@code retrieve()} would hand back a {@code null}
     * body and the userinfo claims would vanish without a trace.
     */
    private static void rejectUnfollowedRedirect(HttpRequest request, ClientHttpResponse response) throws IOException {
        throw new RestClientException("OAuth2 provider endpoint %s answered with redirect %s, which was not followed."
                .formatted(withoutQuery(request.getURI()), response.getStatusCode()));
    }

    /**
     * The logout URI carries the ID token in {@code id_token_hint} and the message of anything thrown here is logged,
     * so the query string must not travel with it.
     */
    private static String withoutQuery(URI uri) {
        String text = uri.toString();
        int queryStart = text.indexOf('?');
        return queryStart < 0 ? text : text.substring(0, queryStart);
    }

    private OAuth2Util() {
        throw new IllegalStateException("Utility class");
    }

    public static void validateAudiences(OAuth2AccessToken accessToken, OAuth2ProviderSettingsDto providerSettings) {

        List<String> clientAudiences = providerSettings.getAudiences();
        List<String> tokenAudiences;
        try {
            tokenAudiences = SignedJWT.parse(accessToken.getTokenValue()).getJWTClaimsSet().getAudience();
        } catch (ParseException e) {
            throw new PlatformAuthenticationException("Could not parse JWT Access Token to validate audiences "
                    + LogRedaction.token(accessToken.getTokenValue()));
        }

        if (!(clientAudiences == null || clientAudiences.isEmpty()
                || tokenAudiences != null && tokenAudiences.stream().anyMatch(clientAudiences::contains))) {
            String errorMessage = "User was not authenticated: audiences %s in access token issued by OAuth2 Provider %s do not match any of audiences %s set for the provider in settings. Token: %s"
                    .formatted(StringUtils.join(tokenAudiences), providerSettings.getName(),
                            StringUtils.join(clientAudiences), LogRedaction.token(accessToken.getTokenValue()));
            throw new PlatformAuthenticationException(errorMessage);
        }

    }

    public static void endUserSession(SecurityContext securityContext) {
        if (securityContext != null) {
            if (securityContext.getAuthentication() == null) {
                logger.warn("No authentication found in security context. User session cannot be ended.");
                return;
            }
            OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) securityContext
                    .getAuthentication();
            AuthenticationSettingsDto authenticationSettingsDto = SettingsCache
                    .getSettings(SettingsSection.AUTHENTICATION);
            String authorizedClientRegistrationId = authenticationToken.getAuthorizedClientRegistrationId();
            OAuth2ProviderSettingsDto provider = authenticationSettingsDto
                    .getOAuth2Providers()
                    .get(authorizedClientRegistrationId);
            if (provider == null) {
                logger
                        .warn("Provider with client ID {} has not been found. User {} will not be logged out on provider side.",
                                authorizedClientRegistrationId, authenticationToken.getName());
                return;
            }
            DefaultOidcUser oidcUser = (DefaultOidcUser) authenticationToken.getPrincipal();
            String idToken = oidcUser.getIdToken().getTokenValue();
            String endSessionEndpoint = provider.getLogoutUrl();
            URI uri = UriComponentsBuilder
                    .fromUriString(endSessionEndpoint)
                    .queryParam("id_token_hint", idToken)
                    .build()
                    .toUri();
            try {
                restClient.get().uri(uri).retrieve().toBodilessEntity();
            } catch (Exception e) {
                logger
                        .error("Failed to log out user {} from OAuth2 provider {} at endpoint {}: {}",
                                authenticationToken.getName(), provider.getName(), endSessionEndpoint, e.getMessage(),
                                e);
            }
        }
    }

    static Map<String, Object> getUserInfo(String userInfoUrl, String accessToken) {
        URI uri = UriComponentsBuilder.fromUriString(userInfoUrl).build().toUri();

        return restClient
                .get()
                .uri(uri)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve()
                .body(new ParameterizedTypeReference<>() {
                });
    }

    private static Map<String, Object> mergeClaims(Map<String, Object> accessTokenClaims,
            Map<String, Object> idTokenClaims, Map<String, Object> userInfoClaims) {
        Map<String, Object> mergedClaims = new HashMap<>();

        if (accessTokenClaims != null) {
            mergedClaims.putAll(accessTokenClaims);
        }
        if (userInfoClaims != null) {
            mergedClaims.putAll(userInfoClaims);
        }
        if (idTokenClaims != null) {
            mergedClaims.putAll(idTokenClaims);
        }

        return mergedClaims;
    }

    /**
     * Finds the OAuth2 provider whose issuer URL equals the given issuer, or {@code null} when none matches. The
     * provider's username claim decides the user's identity, so an ambiguous match (two providers sharing an issuer)
     * fails authentication instead of silently picking one.
     */
    public static OAuth2ProviderSettingsDto findProviderByIssuer(AuthenticationSettingsDto settings, String issuerUri) {
        if (settings == null || issuerUri == null || settings.getOAuth2Providers() == null) {
            return null;
        }
        List<OAuth2ProviderSettingsDto> matches = settings
                .getOAuth2Providers()
                .values()
                .stream()
                .filter(p -> issuerUri.equals(p.getIssuerUrl()))
                .toList();
        if (matches.size() > 1) {
            throw new PlatformAuthenticationException(
                    "Multiple OAuth2 providers are configured with issuer '%s'; provider selection is ambiguous."
                            .formatted(issuerUri));
        }
        return matches.isEmpty() ? null : matches.getFirst();
    }

    /**
     * Returns the claim name that identifies the user for the given provider: the provider's configured username claim
     * when non-blank, otherwise {@link OAuth2Constants#TOKEN_USERNAME_CLAIM_NAME}.
     */
    public static String effectiveUsernameClaim(OAuth2ProviderSettingsDto providerSettings) {
        return providerSettings != null && StringUtils.isNotBlank(providerSettings.getUsernameClaim())
                ? providerSettings.getUsernameClaim()
                : OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME;
    }

    /**
     * Resolves the platform identity from token claims. The identity is the value of the effective username claim and
     * must be a non-blank string. There is deliberately no fallback to any other claim: which claim identifies the user
     * is an operator decision made via the provider settings.
     *
     * @throws PlatformAuthenticationException when the claim is absent, blank, or not a string
     */
    public static String resolveUsername(OAuth2ProviderSettingsDto providerSettings, Map<String, Object> claims) {
        String claimName = effectiveUsernameClaim(providerSettings);
        Object value = claims == null ? null : claims.get(claimName);
        if (value == null) {
            throw new PlatformAuthenticationException(
                    "Username claim '%s' not found in token claims.".formatted(claimName));
        }
        if (!(value instanceof String username) || StringUtils.isBlank(username)) {
            throw new PlatformAuthenticationException(
                    "Username claim '%s' must be a non-blank string value.".formatted(claimName));
        }
        return username;
    }

    /**
     * Lenient variant of {@link #resolveUsername(OAuth2ProviderSettingsDto, Map)} for logging contexts where a missing
     * username must not fail the request.
     */
    public static String resolveUsernameOrNull(OAuth2ProviderSettingsDto providerSettings, Map<String, Object> claims) {
        Object value = claims == null ? null : claims.get(effectiveUsernameClaim(providerSettings));
        return value instanceof String username && StringUtils.isNotBlank(username) ? username : null;
    }

    public static Map<String, Object> getAllClaimsAvailable(OAuth2ProviderSettingsDto providerSettings,
            String accessTokenValue, OidcIdToken idToken) {
        Map<String, Object> userInfoClaims = null;
        if (providerSettings != null && providerSettings.getUserInfoUrl() != null) {
            try {
                userInfoClaims = getUserInfo(providerSettings.getUserInfoUrl(), accessTokenValue);
            } catch (Exception e) {
                logger
                        .warn("Could not access User Info Endpoint {}: {}", providerSettings.getUserInfoUrl(),
                                e.getMessage());
            }
        }

        Map<String, Object> accessTokenClaims;
        try {
            accessTokenClaims = SignedJWT.parse(accessTokenValue).getJWTClaimsSet().getClaims();
        } catch (ParseException e) {
            String message = "Could not convert access token to JWT and extract claims. Reason: %s Token: %s"
                    .formatted(e.getMessage(), LogRedaction.token(accessTokenValue));
            throw new PlatformAuthenticationException(message);
        }

        Map<String, Object> claims = mergeClaims(accessTokenClaims, idToken == null ? null : idToken.getClaims(),
                userInfoClaims);
        String username = resolveUsername(providerSettings, claims);
        claims.put(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, username);
        return claims;
    }

}
