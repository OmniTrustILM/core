package com.czertainly.core.security.authn.client;

import com.czertainly.api.model.core.logging.enums.*;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.model.auth.AuthenticationRequestDto;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.security.authn.client.dto.AuthenticationResponseDto;
import com.czertainly.core.security.authn.client.dto.UserDetailsDto;
import com.czertainly.core.security.exception.AuthenticationServiceException;
import com.czertainly.core.service.AuditLogService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.CertificateUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class CzertainlyAuthenticationClient extends CzertainlyBaseAuthenticationClient {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ObjectMapper objectMapper;
    private final String customAuthServiceBaseUrl;
    private final AuthenticationCache authenticationCache;

    @Value("${server.ssl.certificate-header-name}")
    private String certificateHeaderName;

    private final AuditLogService auditLogService;

    public CzertainlyAuthenticationClient(
            @Autowired AuditLogService auditLogService,
            @Autowired ObjectMapper objectMapper,
            @Autowired AuthenticationCache authenticationCache,
            @Value("${auth-service.base-url}") String customAuthServiceBaseUrl) {
        this.objectMapper = objectMapper;
        this.auditLogService = auditLogService;
        this.authenticationCache = authenticationCache;
        this.customAuthServiceBaseUrl = customAuthServiceBaseUrl;
    }

    public AuthenticationInfo authenticateSystemUser(String username) {
        return authenticationCache.getOrAuthenticateSystemUser(
                username, () -> authenticate(AuthMethod.USER_PROXY, username, false));
    }

    public AuthenticationInfo authenticateByUserUuid(UUID userUuid) {
        return authenticationCache.getOrAuthenticateByUserUuid(
                userUuid, () -> authenticate(AuthMethod.USER_PROXY, userUuid, false));
    }

    public AuthenticationInfo authenticateByCertificate(String rawCertHeader, String certificateThumbprint) {
        return authenticationCache.getOrAuthenticateByCertificate(
                certificateThumbprint, () -> authenticate(AuthMethod.CERTIFICATE, rawCertHeader, false));
    }

    public AuthenticationInfo authenticateByToken(Map<String, Object> claims) {
        String jti = (String) claims.get("jti");
        return authenticationCache.getOrAuthenticateByToken(
                jti, () -> authenticate(AuthMethod.TOKEN, claims, false));
    }

    public AuthenticationInfo authenticate(AuthMethod authMethod, Object authData, boolean isLocalhostRequest) throws AuthenticationException {

        AuthenticationRequestDto authRequest = getAuthPayload(authMethod, authData, isLocalhostRequest);
        if (logger.isDebugEnabled()) {
            ActorType actorType = LoggingHelper.getActorType();
            logger.debug("Going to authenticate {}user with {} auth method. {}", actorType == null || actorType == ActorType.USER ? "" : actorType.getLabel() + " ", authRequest.getAuthMethod().getLabel(), authRequest.getAuthData(true));
        }

        try {

            WebClient.RequestHeadersSpec<?> request = getClient(customAuthServiceBaseUrl)
                    .post()
                    .uri("/auth")
                    .body(Mono.just(authRequest), AuthenticationRequestDto.class)
                    .accept(MediaType.APPLICATION_JSON);

            AuthenticationResponseDto response = request
                    .retrieve()
                    .bodyToMono(AuthenticationResponseDto.class)
                    .block();

            if (response == null) {
                String message = "Empty response received from authentication service";
                AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, authRequest.getAuthData(false));
                throw new CzertainlyAuthenticationException(message);
            }
            return createAuthenticationInfo(authRequest.getAuthMethod(), response);
        } catch (WebClientResponseException.InternalServerError | WebClientRequestException | IllegalStateException e) {
            String message = "An error occurred when calling authentication service: " + e.getMessage();
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, authRequest.getAuthData(false));
            throw new CzertainlyAuthenticationException(message, e);
        } catch (AuthenticationServiceException e) {
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, e.getException().getMessage(), authRequest.getAuthData(false));
            throw new CzertainlyAuthenticationException(e.getException().getMessage(), e);
        }
    }

    private AuthenticationRequestDto getAuthPayload(AuthMethod authMethod, Object authData, boolean isLocalhostRequest) {
        AuthenticationRequestDto requestDto = new AuthenticationRequestDto();
        requestDto.setAuthMethod(authMethod);
        switch (authMethod) {
            case NONE -> checkLocalhostUser(requestDto, isLocalhostRequest);
            case CERTIFICATE -> {
                try {
                    String certificateInHeader = URLDecoder.decode((String) authData, StandardCharsets.UTF_8);
                    requestDto.setCertificateContent(CertificateUtil.normalizeCertificateContent(certificateInHeader));
                } catch (Exception e) {
                    LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.CERTIFICATE);
                    String message = "Could not parse certificate for authentication. Certificate: " + authData;
                    AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, authData.toString());
                    throw new CzertainlyAuthenticationException(message);
                }
            }
            case TOKEN -> requestDto.setAuthenticationTokenUserClaims((Map<String, Object>) authData);
            case USER_PROXY -> {
                if (authData instanceof UUID) requestDto.setUserUuid(authData.toString());
                else requestDto.setSystemUsername((String) authData);
            }
            default -> {
                // No action required for other authentication methods
            }
        }

        // update MDC for actor logging before authentication
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, requestDto.getAuthMethod());

        return requestDto;
    }

    private void checkLocalhostUser(AuthenticationRequestDto requestDto, boolean isLocalhostRequest) {
        if (isLocalhostRequest) {
            AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
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
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, userDetails.getUser().getUuid(), userDetails.getUser().getUsername());

            return new AuthenticationInfo(
                    authMethod,
                    userDetails.getUser().getUuid(),
                    userDetails.getUser().getUsername(),
                    userDetails.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList()),
                    response.getData()
            );
        } catch (JsonProcessingException e) {
            throw new CzertainlyAuthenticationException("The response from the authentication service could not be parsed.", e);
        }
    }

}
