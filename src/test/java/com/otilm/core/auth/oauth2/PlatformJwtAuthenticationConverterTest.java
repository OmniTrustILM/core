package com.otilm.core.auth.oauth2;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.logging.LogRedaction;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.AuthenticationSettingsSnapshot;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Util;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
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

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlatformJwtAuthenticationConverterTest {

    private static final String ISSUER_URL = "https://issuer.example.com";
    private static final String TOKEN_VALUE = "header.payload.signature";

    @Mock
    private PlatformAuthenticationClient authenticationClient;

    @Mock
    private AuditLogInternalService auditLogService;

    private PlatformJwtAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new PlatformJwtAuthenticationConverter();
        converter.setAuthenticationClient(authenticationClient);
        converter.setAuditLogService(auditLogService);
        SecurityContextHolder.clearContext();
        AuthenticationSnapshotRequestHolder.clear();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        AuthenticationSnapshotRequestHolder.clear();
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
        when(authenticationClient.authenticateByToken(claims, 1L)).thenReturn(authenticatedInfo());

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
                MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock
                    .when(SettingsCache::getAuthenticationSnapshot)
                    .thenReturn(new AuthenticationSettingsSnapshot(authSettingsWithProvider(ISSUER_URL), 1L));
            oauth2Mock.when(() -> OAuth2Util.findProviderByIssuer(any(), anyString())).thenCallRealMethod();
            oauth2Mock
                    .when(() -> OAuth2Util
                            .getAllClaimsAvailable(argThat(p -> p != null && ISSUER_URL.equals(p.getIssuerUrl())),
                                    eq(TOKEN_VALUE), isNull()))
                    .thenReturn(claims);

            // when
            AbstractAuthenticationToken result = converter.convert(jwt);

            // then
            verify(authenticationClient).authenticateByToken(claims, 1L);
            assertInstanceOf(PlatformAuthenticationToken.class, result);
        }
    }

    @Test
    void claimsExtractionFailure_logsAuditAndRethrows() throws MalformedURLException {
        // given
        Jwt jwt = mockJwt(ISSUER_URL);
        PlatformAuthenticationException cause = new PlatformAuthenticationException("claims extraction failed");

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
                MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock
                    .when(SettingsCache::getAuthenticationSnapshot)
                    .thenReturn(new AuthenticationSettingsSnapshot(authSettingsWithProvider(ISSUER_URL), 1L));
            oauth2Mock.when(() -> OAuth2Util.findProviderByIssuer(any(), anyString())).thenCallRealMethod();
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(any(), anyString(), isNull())).thenThrow(cause);

            // when / then
            PlatformAuthenticationException thrown = assertThrows(PlatformAuthenticationException.class,
                    () -> converter.convert(jwt));
            assertSame(cause, thrown);
            verify(auditLogService)
                    .logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, cause.getMessage(),
                            LogRedaction.token(TOKEN_VALUE));
        }
    }

    @Test
    void claimsExtractionFailure_withSignedJwt_recordsHeaderAndPayloadOnly() throws Exception {
        // given - the request's own, validly signed bearer JWT, refused because it has no username claim
        SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().issuer(ISSUER_URL).subject("alice").build());
        signedJwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        String tokenValue = signedJwt.serialize();
        String[] parts = tokenValue.split("\\.");
        String headerAndPayload = parts[0] + "." + parts[1];

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn(tokenValue);
        when(jwt.getIssuer()).thenReturn(new URL(ISSUER_URL));
        PlatformAuthenticationException cause = new PlatformAuthenticationException(
                "Username claim 'username' not found in token claims.");

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
                MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock
                    .when(SettingsCache::getAuthenticationSnapshot)
                    .thenReturn(new AuthenticationSettingsSnapshot(authSettingsWithProvider(ISSUER_URL), 1L));
            oauth2Mock.when(() -> OAuth2Util.findProviderByIssuer(any(), anyString())).thenCallRealMethod();
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(any(), eq(tokenValue), isNull())).thenThrow(cause);

            // when / then
            assertThrows(PlatformAuthenticationException.class, () -> converter.convert(jwt));
            verify(auditLogService)
                    .logAuthentication(Operation.AUTHENTICATION, OperationResult.FAILURE, cause.getMessage(),
                            headerAndPayload);
        }
    }

    @Test
    void issuerNotMatchingAnyProvider_passesNullProviderSettingsToGetClaims() throws MalformedURLException {
        // given - JWT issuer does not match the single configured provider
        Jwt jwt = mockJwt("https://unknown-issuer.example.com");
        Map<String, Object> claims = Map.of("username", "alice");
        when(authenticationClient.authenticateByToken(any(), anyLong())).thenReturn(authenticatedInfo());

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
                MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock
                    .when(SettingsCache::getAuthenticationSnapshot)
                    .thenReturn(new AuthenticationSettingsSnapshot(authSettingsWithProvider(ISSUER_URL), 1L));
            oauth2Mock.when(() -> OAuth2Util.findProviderByIssuer(any(), anyString())).thenCallRealMethod();
            oauth2Mock
                    .when(() -> OAuth2Util.getAllClaimsAvailable(isNull(), eq(TOKEN_VALUE), isNull()))
                    .thenReturn(claims);

            // when
            converter.convert(jwt);

            // then - null provider settings forwarded because no configured issuer matched the JWT
            oauth2Mock.verify(() -> OAuth2Util.getAllClaimsAvailable(isNull(), eq(TOKEN_VALUE), isNull()));
        }
    }

    @Test
    void publishedSnapshot_isPreferredOverTheCurrentSettings() throws MalformedURLException {
        // given - the decoder validated the token against generation 7, and the settings changed since
        Jwt jwt = mockJwt(ISSUER_URL);
        Map<String, Object> claims = Map.of("username", "alice", "jti", "jti-123");
        AuthenticationSettingsDto validatedSettings = authSettingsWithProvider(ISSUER_URL);
        AuthenticationSnapshotRequestHolder.set(new AuthenticationSettingsSnapshot(validatedSettings, 7L));
        when(authenticationClient.authenticateByToken(any(), anyLong())).thenReturn(authenticatedInfo());

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
                MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock
                    .when(SettingsCache::getAuthenticationSnapshot)
                    .thenReturn(new AuthenticationSettingsSnapshot(
                            authSettingsWithProvider("https://rotated-issuer.example.com"), 8L));
            oauth2Mock.when(() -> OAuth2Util.findProviderByIssuer(any(), anyString())).thenCallRealMethod();
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(any(), anyString(), isNull())).thenReturn(claims);

            // when
            converter.convert(jwt);

            // then - identity and cache generation come from the snapshot the token was validated against
            verify(authenticationClient).authenticateByToken(claims, 7L);
            oauth2Mock.verify(() -> OAuth2Util.findProviderByIssuer(same(validatedSettings), eq(ISSUER_URL)));
        }
    }

    @Test
    void noPublishedSnapshot_fallsBackToTheCurrentSettings() throws MalformedURLException {
        // given - the converter is invoked without the decoder having published anything
        Jwt jwt = mockJwt(ISSUER_URL);
        Map<String, Object> claims = Map.of("username", "alice", "jti", "jti-123");
        when(authenticationClient.authenticateByToken(any(), anyLong())).thenReturn(authenticatedInfo());

        try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class);
                MockedStatic<OAuth2Util> oauth2Mock = mockStatic(OAuth2Util.class)) {
            settingsMock
                    .when(SettingsCache::getAuthenticationSnapshot)
                    .thenReturn(new AuthenticationSettingsSnapshot(authSettingsWithProvider(ISSUER_URL), 5L));
            oauth2Mock.when(() -> OAuth2Util.findProviderByIssuer(any(), anyString())).thenCallRealMethod();
            oauth2Mock.when(() -> OAuth2Util.getAllClaimsAvailable(any(), anyString(), isNull())).thenReturn(claims);

            // when
            converter.convert(jwt);

            // then
            verify(authenticationClient).authenticateByToken(claims, 5L);
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
