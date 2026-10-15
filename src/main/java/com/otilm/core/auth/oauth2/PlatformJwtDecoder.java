package com.otilm.core.auth.oauth2;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.logging.LogRedaction;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAnonymousToken;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.AuthenticationSettingsSnapshot;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.OAuth2Util;
import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

@Component
public class PlatformJwtDecoder implements JwtDecoder {

    @Value("${server.port}")
    private String port;

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Value("${server.ssl.enabled}")
    private boolean sslEnabled;

    private static final Logger logger = LoggerFactory.getLogger(PlatformJwtDecoder.class);

    private AuditLogInternalService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogInternalService auditLogService) {
        this.auditLogService = auditLogService;
    }

    /**
     * Validates the token against the provider configuration of a single authentication-settings snapshot and publishes
     * that snapshot through {@link AuthenticationSnapshotRequestHolder}, so the identity resolution that follows in the
     * same request cannot run against a concurrently updated configuration.
     */
    @Override
    public Jwt decode(String token) throws JwtException {
        if (!isAuthenticationNeeded()) {
            return null;
        }
        SignedJWT signedJWT;
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.TOKEN);
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            String message = "Token is not an instance of Signed JWT.";
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, LogRedaction.token(token));
            throw new PlatformAuthenticationException(message);
        }
        JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            String message = "Could not extract claims from JWT.";
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, LogRedaction.token(token));
            throw new PlatformAuthenticationException(message);
        }
        String issuerUri = claimsSet.getIssuer();
        if (issuerUri == null) {
            String message = "Issuer URI is not present in JWT.";
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, LogRedaction.token(token));
            throw new PlatformAuthenticationException(message);
        }

        AuthenticationSettingsSnapshot snapshot = SettingsCache.getAuthenticationSnapshot();
        AuthenticationSnapshotRequestHolder.set(snapshot);
        OAuth2ProviderSettingsDto providerSettings = OAuth2Util.findProviderByIssuer(snapshot.settings(), issuerUri);

        if (providerSettings == null) {
            String message = "No OAuth2 Provider with issuer URI '%s' configured for authentication with JWT token"
                    .formatted(issuerUri);
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, LogRedaction.token(token));
            throw new PlatformAuthenticationException(message);
        }

        int skew = providerSettings.getSkew();
        List<String> audiences = providerSettings.getAudiences();

        NimbusJwtDecoder jwtDecoder;
        try {
            if (providerSettings.getJwkSetUrl() == null && providerSettings.getJwkSet() == null) {
                jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
            } else {
                String protocol = sslEnabled ? "https" : "http";
                String jwkSetUrl = providerSettings.getJwkSetUrl() != null
                        ? providerSettings.getJwkSetUrl()
                        : protocol + "://localhost:" + port + contextPath + "/oauth2/" + providerSettings.getName()
                                + "/jwkSet";
                jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUrl).build();
            }
        } catch (Exception e) {
            String message = "Could not authenticate user using JWT token: %s".formatted(e.getMessage());
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, LogRedaction.token(token));
            throw new PlatformAuthenticationException(message);
        }

        OAuth2TokenValidator<Jwt> combinedValidator = getJwtOAuth2TokenValidator(skew, audiences, issuerUri);
        jwtDecoder.setJwtValidator(combinedValidator);
        try {
            return jwtDecoder.decode(token);
        } catch (JwtException e) {
            String message = "Could not authenticate user using JWT token: %s".formatted(e.getMessage());
            AuthHelper.logAndAuditAuthFailure(logger, auditLogService, message, LogRedaction.token(token));
            throw new PlatformAuthenticationException(message);
        }
    }

    private static OAuth2TokenValidator<Jwt> getJwtOAuth2TokenValidator(int skew, List<String> audiences,
            String issuerUri) {
        OAuth2TokenValidator<Jwt> clockSkewValidator = new JwtTimestampValidator(Duration.ofSeconds(skew));
        OAuth2TokenValidator<Jwt> audienceValidator = new DelegatingOAuth2TokenValidator<>();

        // Add audience validation
        if (!audiences.isEmpty()) {
            audienceValidator = new JwtClaimValidator<>("aud",
                    (List<String> aud) -> aud.stream().anyMatch(audiences::contains));
        }

        return JwtValidators
                .createDefaultWithValidators(
                        List.of(new JwtIssuerValidator(issuerUri), clockSkewValidator, audienceValidator));
    }

    private boolean isAuthenticationNeeded() {
        SecurityContext context = SecurityContextHolder.getContext();
        return (context == null || context.getAuthentication() == null
                || context.getAuthentication() instanceof PlatformAnonymousToken anonymousToken
                        && !anonymousToken.isAccessingPermitAllEndpoint());
    }

}
