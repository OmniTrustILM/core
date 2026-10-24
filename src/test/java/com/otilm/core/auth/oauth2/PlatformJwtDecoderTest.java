package com.otilm.core.auth.oauth2;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.logging.LogRedaction;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.LoopbackWireMock;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PlatformJwtDecoderTest {

    private final AuditLogInternalService auditLogService = mock(AuditLogInternalService.class);
    private final PlatformJwtDecoder decoder = new PlatformJwtDecoder();
    private AuthenticationSettingsDto previousSettings;
    private static WireMockServer issuer;
    private static RSAKey signingKey;

    @BeforeAll
    static void startIssuer() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("delegation-key").generate();
        issuer = LoopbackWireMock.start();
    }

    @AfterAll
    static void stopIssuer() {
        issuer.stop();
    }

    @BeforeEach
    void setUp() {
        issuer.resetAll();
        issuer.stubFor(get("/jwks").willReturn(okJson(new JWKSet(signingKey.toPublicJWK()).toString())));
        decoder.setAuditLogService(auditLogService);
        SecurityContextHolder.clearContext();
        previousSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
    }

    @AfterEach
    void restore() {
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, previousSettings);
        MDC.clear();
        AuthenticationSnapshotRequestHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void delegatedTokenUsesTheCurrentAllowlistBeforeAnyIdentityLookup() throws Exception {
        var provider = configureProvider(List.of("mcp"));
        String token = delegatedToken(Map.of("client_id", "mcp"));
        assertThat(decoder.decode(token).getSubject()).isEqualTo("alice");
        provider.setAllowedDelegates(List.of());
        publishProvider(provider);
        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasMessageContaining("delegation-provider")
                .hasMessageContaining("client_id")
                .hasMessageContaining("mcp");
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE),
                        org.mockito.ArgumentMatchers.contains("mcp"), eq(LogRedaction.token(token)));
    }

    @Test
    void invalidActorIsRefusedButOrdinaryTokenIsUnchanged() throws Exception {
        configureProvider(List.of());
        String invalidToken = delegatedToken("mcp");
        assertThatThrownBy(() -> decoder.decode(invalidToken))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasMessageContaining("act");
        assertThat(decoder.decode(delegatedToken(null)).getSubject()).isEqualTo("alice");
        assertThat(LoggingHelper.getActorInfo().delegate()).isNull();
    }

    @Test
    void unverifiedActorIsNeverUsedForDelegationDiagnostics() throws Exception {
        configureProvider(List.of());
        String token = delegatedToken(Map.of("client_id", "untrusted-delegate"));
        var wrongKey = new RSAKeyGenerator(2048).keyID(signingKey.getKeyID()).generate();
        issuer.stubFor(get("/jwks").willReturn(okJson(new JWKSet(wrongKey.toPublicJWK()).toString())));
        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasMessageContaining("signature")
                .hasMessageNotContaining("untrusted-delegate");
    }

    private OAuth2ProviderSettingsDto configureProvider(List<String> delegates) {
        var provider = new OAuth2ProviderSettingsDto();
        provider.setName("delegation-provider");
        provider.setIssuerUrl(issuer.baseUrl());
        provider.setJwkSetUrl(issuer.baseUrl() + "/jwks");
        provider.setAllowedDelegates(delegates);
        publishProvider(provider);
        return provider;
    }

    private void publishProvider(OAuth2ProviderSettingsDto provider) {
        var settings = new AuthenticationSettingsDto();
        settings.setOAuth2Providers(Map.of(provider.getName(), provider));
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, settings);
    }

    private String delegatedToken(Object actor) throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer.baseUrl())
                .subject("alice")
                .expirationTime(new Date(System.currentTimeMillis() + 60_000));
        if (actor != null) {
            claims.claim("act", actor);
        }
        var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                claims.build());
        token.sign(new RSASSASigner(signingKey));
        return token.serialize();
    }

    @Test
    void aTokenFromAnUnknownIssuer_isRecordedWithoutItsSignature() throws Exception {
        // given
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().issuer("https://unknown-issuer.example").subject("alice").build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        String token = jwt.serialize();
        String[] parts = token.split("\\.");

        // when
        assertThrows(PlatformAuthenticationException.class, () -> decoder.decode(token));

        // then
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), anyString(),
                        eq(parts[0] + "." + parts[1]));
    }

    @Test
    void aTokenThatIsNotAJwt_isRecordedAsRedacted() {
        // given
        String token = "opaque-token-value";

        // when
        assertThrows(PlatformAuthenticationException.class, () -> decoder.decode(token));

        // then
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), anyString(),
                        eq(LogRedaction.REDACTED));
    }

    @Test
    void aTokenWithoutAnIssuer_isRecordedWithoutItsSignature() throws Exception {
        // given
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().subject("alice").build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        String token = jwt.serialize();
        String[] parts = token.split("\\.");

        // when
        assertThrows(PlatformAuthenticationException.class, () -> decoder.decode(token));

        // then
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), anyString(),
                        eq(parts[0] + "." + parts[1]));
    }
}
