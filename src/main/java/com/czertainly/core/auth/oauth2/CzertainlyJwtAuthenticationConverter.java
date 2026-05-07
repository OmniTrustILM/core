package com.czertainly.core.auth.oauth2;

import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authn.CzertainlyUserDetails;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import com.czertainly.core.service.AuditLogService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.OAuth2Util;
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
public class CzertainlyJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger logger = LoggerFactory.getLogger(CzertainlyJwtAuthenticationConverter.class);

    private CzertainlyAuthenticationClient authenticationClient;

    private AuditLogService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Autowired
    public void setAuthenticationClient(CzertainlyAuthenticationClient authenticationClient) {
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
        } catch (CzertainlyAuthenticationException e) {
            auditLogService.logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, e.getMessage(), source.getTokenValue());
            throw e;
        }

        AuthenticationInfo authInfo = authenticationClient.authenticateByToken(claims);
        CzertainlyUserDetails userDetails = new CzertainlyUserDetails(authInfo);
        // Provider settings will not be null, otherwise converter would not have been reached from decoder
        logger.debug("User '{}' has been authenticated using JWT from OAuth2 Provider '{}'.", userDetails.getUsername(), providerSettings == null ? " " : providerSettings.getName());
        return new CzertainlyAuthenticationToken(userDetails);
    }
}
