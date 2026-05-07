package com.czertainly.core.auth.oauth2;

import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import com.czertainly.core.service.AuditLogService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.OAuth2Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CzertainlyJwtAuthenticationConverterTest {

    private static final String ISSUER_URL = "https://issuer.example.com";
    private static final String TOKEN_VALUE = "header.payload.signature";

    @Mock
    private CzertainlyAuthenticationClient authenticationClient;

    @Mock
    private AuditLogService auditLogService;

    private CzertainlyJwtAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new CzertainlyJwtAuthenticationConverter();
        converter.setAuthenticationClient(authenticationClient);
        converter.setAuditLogService(auditLogService);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void nullJwt_returnsCurrentSecurityContextAuthentication() {
        // given - a prior filter already placed an authenticated token in the context
        AbstractAuthenticationToken existingAuth = mock(AbstractAuthenticationToken.class);
        var ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(existingAuth);
        SecurityContextHolder.setContext(ctx);

        // when
        AbstractAuthenticationToken result = converter.convert(null);

        // then
        assertSame(existingAuth, result);
    }

    @Test
    void nullJwt_withEmptySecurityContext_returnsNull() {
        // given - no prior authentication in the context (SecurityContextHolder cleared in @BeforeEach)

        // when
        AbstractAuthenticationToken result = converter.convert(null);

        // then
        assertNull(result);
    }

    @Test
    void validJwt_callsAuthClientWithExtractedClaimsAndReturnsAuthToken() throws MalformedURLException {
        // given
        Jwt jwt = mockJwt(ISSUER_URL);
        Map<String, Object> claims = Map.of("username", "alice", "jti", "jti-123");
        when(authenticationClient.authenticateByToken(claims)).thenReturn(authenticatedInfo());

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
             MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock.when(() -> SettingsCache.getSettings(SettingsSection.AUTHENTICATION))
                    .thenReturn(authSettingsWithProvider(ISSUER_URL));
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(
                            argThat(p -> p != null && ISSUER_URL.equals(p.getIssuerUrl())),
                            eq(TOKEN_VALUE), isNull()))
                    .thenReturn(claims);

            // when
            AbstractAuthenticationToken result = converter.convert(jwt);

            // then
            verify(authenticationClient).authenticateByToken(claims);
            assertInstanceOf(CzertainlyAuthenticationToken.class, result);
        }
    }

    @Test
    void claimsExtractionFailure_logsAuditAndRethrows() throws MalformedURLException {
        // given
        Jwt jwt = mockJwt(ISSUER_URL);
        CzertainlyAuthenticationException cause = new CzertainlyAuthenticationException("claims extraction failed");

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
             MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock.when(() -> SettingsCache.getSettings(SettingsSection.AUTHENTICATION))
                    .thenReturn(authSettingsWithProvider(ISSUER_URL));
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(any(), anyString(), isNull()))
                    .thenThrow(cause);

            // when / then
            CzertainlyAuthenticationException thrown = assertThrows(
                    CzertainlyAuthenticationException.class, () -> converter.convert(jwt));
            assertSame(cause, thrown);
            verify(auditLogService).logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, cause.getMessage(), TOKEN_VALUE);
        }
    }

    @Test
    void issuerNotMatchingAnyProvider_passesNullProviderSettingsToGetClaims() throws MalformedURLException {
        // given - JWT issuer does not match the single configured provider
        Jwt jwt = mockJwt("https://unknown-issuer.example.com");
        Map<String, Object> claims = Map.of("username", "alice");
        when(authenticationClient.authenticateByToken(any())).thenReturn(authenticatedInfo());

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
             MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock.when(() -> SettingsCache.getSettings(SettingsSection.AUTHENTICATION))
                    .thenReturn(authSettingsWithProvider(ISSUER_URL));
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(isNull(), eq(TOKEN_VALUE), isNull()))
                    .thenReturn(claims);

            // when
            converter.convert(jwt);

            // then - null provider settings forwarded because no configured issuer matched the JWT
            oauth2Mock.verify(() -> OAuth2Util.getAllClaimsAvailable(isNull(), eq(TOKEN_VALUE), isNull()));
        }
    }

    // --- helpers ---

    private static Jwt mockJwt(String issuerUrl) throws MalformedURLException {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn(TOKEN_VALUE);
        when(jwt.getIssuer()).thenReturn(new URL(issuerUrl));
        return jwt;
    }

    private static AuthenticationSettingsDto authSettingsWithProvider(String issuerUrl) {
        OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
        provider.setName("test-provider");
        provider.setIssuerUrl(issuerUrl);
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        settings.setOAuth2Providers(Map.of("test-provider", provider));
        return settings;
    }

    private static AuthenticationInfo authenticatedInfo() {
        return new AuthenticationInfo(AuthMethod.TOKEN, "uuid-1", "alice",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
