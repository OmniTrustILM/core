package com.otilm.core.auth.oauth2;

import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Util;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class PlatformJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger logger = LoggerFactory.getLogger(PlatformJwtAuthenticationConverter.class);

    private PlatformAuthenticationClient authenticationClient;

    private AuditLogInternalService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogInternalService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Autowired
    public void setAuthenticationClient(PlatformAuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    @Override
    public AbstractAuthenticationToken convert(@Nullable Jwt source) {
        if (source == null) {
            return (AbstractAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        }

        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        OAuth2ProviderSettingsDto providerSettings = authenticationSettings.getOAuth2Providers().values().stream().filter(p -> p.getIssuerUrl().equals(source.getIssuer().toString())).findFirst().orElse(null);

        Map<String, Object> claims;
        try {
            claims = OAuth2Util.getAllClaimsAvailable(providerSettings, source.getTokenValue(), null);
        } catch (PlatformAuthenticationException e) {
            auditLogService.logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, e.getMessage(), source.getTokenValue());
            throw e;
        }

        AuthenticationInfo authInfo = authenticationClient.authenticateByToken(claims);
        PlatformUserDetails userDetails = new PlatformUserDetails(authInfo);
        // Provider settings will not be null, otherwise converter would not have been reached from decoder
        logger.debug("User '{}' has been authenticated using JWT from OAuth2 Provider '{}'.", userDetails.getUsername(), providerSettings == null ? " " : providerSettings.getName());
        return new PlatformAuthenticationToken(userDetails);
    }
}
