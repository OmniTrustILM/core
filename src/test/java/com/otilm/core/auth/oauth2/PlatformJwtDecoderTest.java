package com.otilm.core.auth.oauth2;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.core.logging.LogRedaction;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PlatformJwtDecoderTest {

    private final AuditLogInternalService auditLogService = mock(AuditLogInternalService.class);
    private final PlatformJwtDecoder decoder = new PlatformJwtDecoder();
    private AuthenticationSettingsDto previousSettings;

    @BeforeEach
    void setUp() {
        decoder.setAuditLogService(auditLogService);
        SecurityContextHolder.clearContext();
        previousSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
    }

    @AfterEach
    void restore() {
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, previousSettings);
        AuthenticationSnapshotRequestHolder.clear();
        SecurityContextHolder.clearContext();
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
