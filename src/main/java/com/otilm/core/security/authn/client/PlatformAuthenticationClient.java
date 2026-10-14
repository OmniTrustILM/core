package com.otilm.core.security.authn.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.AuthenticationRequestDto;
import com.otilm.core.security.authn.ForwardedClientCertificateParser;
import com.otilm.core.security.authn.ForwardedClientCertificateParser.ParsedCertificate;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.dto.AuthenticationResponseDto;
import com.otilm.core.security.authn.client.dto.UserDetailsDto;
import com.otilm.core.security.exception.AuthenticationServiceException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.AuthHelper;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

@Component
public class PlatformAuthenticationClient extends PlatformBaseAuthenticationClient {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ObjectMapper objectMapper;
    private final String customAuthServiceBaseUrl;
    private final AuthenticationCache authenticationCache;

    private final AuditLogInternalService auditLogService;

    public PlatformAuthenticationClient(@Autowired AuditLogInternalService auditLogService,
            @Autowired ObjectMapper objectMapper, @Autowired AuthenticationCache authenticationCache,
            @Value("${auth-service.base-url}") String customAuthServiceBaseUrl) {
        this.objectMapper = objectMapper;
        this.auditLogService = auditLogService;
        this.authenticationCache = authenticationCache;
        this.customAuthServiceBaseUrl = customAuthServiceBaseUrl;
    }

    public AuthenticationInfo authenticateSystemUser(String username) {
        return restoreActorMdc(authenticationCache
                .getOrAuthenticateSystemUser(username, () -> authenticate(AuthMethod.USER_PROXY, username, false)));
    }

    public AuthenticationInfo authenticateByUserUuid(UUID userUuid) {
        return restoreActorMdc(authenticationCache
                .getOrAuthenticateByUserUuid(userUuid, () -> authenticate(AuthMethod.USER_PROXY, userUuid, false)));
    }

    public AuthenticationInfo authenticateByCertificate(ParsedCertificate certificate) {
        return restoreActorMdc(authenticationCache
                .getOrAuthenticateByCertificate(certificate.thumbprint(),
                        () -> authenticate(AuthMethod.CERTIFICATE, certificate, false)));
    }

    public AuthenticationInfo authenticateByToken(Map<String, Object> claims, long settingsGeneration) {
        return restoreActorMdc(authenticationCache
                .getOrAuthenticateByToken(stringClaim(claims, JwtClaimNames.ISS),
                        stringClaim(claims, JwtClaimNames.JTI), settingsGeneration,
                        () -> authenticate(AuthMethod.TOKEN, claims, false)));
    }

    /**
     * Returns the claim value when it is a string, {@code null} otherwise. The token cache is keyed on the issuer and
     * the {@code jti}; a claim of any other shape leaves the key incomplete, and an incomplete key must skip the cache
     * rather than let one token share an entry with another.
     */
    private static String stringClaim(Map<String, Object> claims, String claimName) {
        Object value = claims.get(claimName);
        return value instanceof String text ? text : null;
    }

    /**
     * Replays the actor MDC side effects of {@link #authenticate} so that a cache hit leaves the MDC in the same state
     * as a cache miss. Anonymous results are never cached, so the loader's anonymous MDC path is unaffected.
     */
    private static AuthenticationInfo restoreActorMdc(AuthenticationInfo authInfo) {
        if (!authInfo.isAnonymous()) {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, authInfo.getAuthMethod());
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, authInfo.getUserUuid(), authInfo.getUsername());
        }
        return authInfo;
    }

    public AuthenticationInfo authenticate(AuthMethod authMethod, Object authData, boolean isLocalhostRequest)
            throws AuthenticationException {

        AuthenticationRequestDto authRequest = getAuthPayload(authMethod, authData, isLocalhostRequest);
        if (logger.isDebugEnabled()) {
            ActorType actorType = LoggingHelper.getActorType();
            logger
                    .debug("Going to authenticate {}user with {} auth method. {}",
                            actorType == null || actorType == ActorType.USER ? "" : actorType.getLabel() + " ",
                            authRequest.getAuthMethod().getLabel(), authRequest.getAuthData(true));
        }

        try {

            WebClient.RequestHeadersSpec<?> request = getClient(customAuthServiceBaseUrl)
                    .post()
                    .uri("/auth")
                    .body(Mono.just(authRequest), AuthenticationRequestDto.class)
                    .accept(MediaType.APPLICATION_JSON);

            AuthenticationResponseDto response = request.retrieve().bodyToMono(AuthenticationResponseDto.class).block();

            if (response == null) {
                String message = "Empty response received from authentication service";
                AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, authRequest.getAuthData(false));
                throw new PlatformAuthenticationException(message);
            }
            return createAuthenticationInfo(authRequest.getAuthMethod(), response);
        } catch (WebClientResponseException.InternalServerError | WebClientRequestException | IllegalStateException e) {
            String message = "An error occurred when calling authentication service: " + e.getMessage();
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, authRequest.getAuthData(false));
            throw new PlatformAuthenticationException(message, e);
        } catch (AuthenticationServiceException e) {
            AuthHelper
                    .logAndAuditAuthFailure(logger, auditLogService, e.getException().getMessage(),
                            authRequest.getAuthData(false));
            throw new PlatformAuthenticationException(e.getException().getMessage(), e);
        }
    }

    private AuthenticationRequestDto getAuthPayload(AuthMethod authMethod, Object authData,
            boolean isLocalhostRequest) {
        AuthenticationRequestDto requestDto = new AuthenticationRequestDto();
        requestDto.setAuthMethod(authMethod);
        switch (authMethod) {
            case NONE -> checkLocalhostUser(requestDto, isLocalhostRequest);
            case CERTIFICATE -> {
                ParsedCertificate certificate = authData instanceof ParsedCertificate parsed
                        ? parsed
                        : parseCertificate(authData);
                requestDto.setCertificateContent(certificate.content());
                requestDto.setCertificateChain(certificate.chain());
            }
            case TOKEN -> requestDto.setAuthenticationTokenUserClaims((Map<String, Object>) authData);
            case USER_PROXY -> {
                if (authData instanceof UUID) {
                    requestDto.setUserUuid(authData.toString());
                } else {
                    requestDto.setSystemUsername((String) authData);
                }
            }
            default -> {
                // No action required for other authentication methods
            }
        }

        // update MDC for actor logging before authentication
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, requestDto.getAuthMethod());

        return requestDto;
    }

    private ParsedCertificate parseCertificate(Object authData) {
        try {
            return ForwardedClientCertificateParser.parse((String) authData);
        } catch (Exception e) {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.CERTIFICATE);
            String message = "Could not parse certificate for authentication.";
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, null);
            throw new PlatformAuthenticationException(message);
        }
    }

    private void checkLocalhostUser(AuthenticationRequestDto requestDto, boolean isLocalhostRequest) {
        if (isLocalhostRequest) {
            AuthenticationSettingsDto authenticationSettings = SettingsCache
                    .getSettings(SettingsSection.AUTHENTICATION);
            if (!authenticationSettings.isDisableLocalhostUser()) {
                requestDto.setSystemUsername(AuthHelper.LOCALHOST_USERNAME);
                requestDto.setAuthMethod(AuthMethod.USER_PROXY);
            }
        }
    }

    private AuthenticationInfo createAuthenticationInfo(AuthMethod authMethod, AuthenticationResponseDto response) {
        if (!response.isAuthenticated()) {
            AuthenticationInfo anonymousUserDetails = AuthenticationInfo.getAnonymousAuthenticationInfo();

            // update MDC for actor logging after successful authentication
            LoggingHelper.putActorInfoWhenNull(ActorType.ANONYMOUS, null, anonymousUserDetails.getUsername());

            return anonymousUserDetails;
        }

        try {
            UserDetailsDto userDetails = objectMapper.readValue(response.getData(), UserDetailsDto.class);

            // update MDC for actor logging after successful authentication
            LoggingHelper
                    .putActorInfoWhenNull(ActorType.USER, userDetails.getUser().getUuid(),
                            userDetails.getUser().getUsername());

            return new AuthenticationInfo(authMethod, userDetails.getUser().getUuid(),
                    userDetails.getUser().getUsername(),
                    userDetails
                            .getRoles()
                            .stream()
                            .map(role -> new SimpleGrantedAuthority(role.getName()))
                            .collect(Collectors.toList()),
                    response.getData());
        } catch (JsonProcessingException e) {
            throw new PlatformAuthenticationException(
                    "The response from the authentication service could not be parsed.", e);
        }
    }

}
