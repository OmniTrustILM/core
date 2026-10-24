package com.otilm.core.auth.oauth2;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Util;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.slf4j.MDC;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PlatformJwtDelegationTest {

    private final PlatformAuthenticationClient client = mock(PlatformAuthenticationClient.class);
    private final PlatformJwtAuthenticationConverter converter = new PlatformJwtAuthenticationConverter();
    private AuthenticationSettingsDto previousSettings;
    private OAuth2ProviderSettingsDto provider;

    @BeforeEach
    void setUp() {
        previousSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        provider = new OAuth2ProviderSettingsDto();
        provider.setName("provider");
        provider.setIssuerUrl("https://issuer.example");
        provider.setAllowedDelegates(List.of("mcp"));
        var settings = new AuthenticationSettingsDto();
        settings.setOAuth2Providers(Map.of("provider", provider));
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, settings);
        converter.setAuthenticationClient(client);
        converter.setAuditLogService(mock(AuditLogInternalService.class));
        MDC.clear();
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.TOKEN);
    }

    @AfterEach
    void clear() {
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, previousSettings);
        AuthenticationSnapshotRequestHolder.clear();
        MDC.clear();
    }

    @Test
    void cachedIdentityDoesNotCarryADelegateToTheNextToken() throws Exception {
        when(client.authenticateByToken(any(), anyLong())).thenReturn(identity());
        converter.convert(jwt(Map.of("client_id", "mcp", "sub", "service-account")));
        assertThat(LoggingHelper.getActorInfo().delegate()).isEqualTo(new DelegateRecord("mcp", "service-account"));
        converter.convert(jwt(null));
        assertThat(LoggingHelper.getActorInfo().delegate()).isNull();
    }

    @Test
    void userinfoCannotReplaceOrCreateDelegationAttribution() throws Exception {
        when(client.authenticateByToken(any(), anyLong())).thenReturn(identity());
        try (MockedStatic<OAuth2Util> oauth = mockStatic(OAuth2Util.class, CALLS_REAL_METHODS)) {
            oauth
                    .when(() -> OAuth2Util.getAllClaimsAvailable(any(), anyString(), isNull()))
                    .thenReturn(Map.of("username", "alice", "act", Map.of("client_id", "spoofed")));
            converter.convert(jwt(Map.of("client_id", "mcp")));
            assertThat(LoggingHelper.getActorInfo().delegate()).isEqualTo(new DelegateRecord("mcp", null));
            converter.convert(jwt(null));
            assertThat(LoggingHelper.getActorInfo().delegate()).isNull();
        }
    }

    @Test
    void disallowedDelegateCannotReachIdentityLookupAndClearsPreviousDelegate() throws Exception {
        LoggingHelper.putDelegateInfo(new DelegateRecord("previous", null));
        Jwt disallowedToken = jwt(Map.of("client_id", "unallowed"));
        assertThatThrownBy(() -> converter.convert(disallowedToken))
                .isInstanceOf(PlatformAuthenticationException.class);
        verifyNoInteractions(client);
        assertThat(LoggingHelper.getActorInfo().delegate()).isNull();
    }

    private Jwt jwt(Object actor) throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", provider.getIssuerUrl());
        claims.put("sub", "user-subject");
        claims.put("username", "alice");
        claims.put("jti", "same-user-token");
        if (actor != null) {
            claims.put("act", actor);
        }
        var token = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), JWTClaimsSet.parse(claims));
        token.sign(new MACSigner("0123456789abcdef0123456789abcdef"));
        return Jwt.withTokenValue(token.serialize()).header("alg", "HS256").claims(c -> c.putAll(claims)).build();
    }

    private AuthenticationInfo identity() {
        return new AuthenticationInfo(AuthMethod.TOKEN, "e9838918-5e7c-4594-aa54-ec4088db6382", "alice", List.of());
    }
}
