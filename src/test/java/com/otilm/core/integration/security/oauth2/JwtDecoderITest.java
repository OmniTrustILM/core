package com.otilm.core.integration.security.oauth2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.core.auth.oauth2.AuthenticationSnapshotRequestHolder;
import com.otilm.core.auth.oauth2.LoginController;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.security.authn.PlatformAnonymousToken;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.oauth2.OAuth2TestUtil;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.settings.AuthenticationSettingsSnapshot;
import com.otilm.core.util.BaseSpringBootTest;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class JwtDecoderITest extends BaseSpringBootTest {

    public static final String AUDIENCE = "your-audience";
    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private SettingRepository settingRepository;

    @Autowired
    private LoginController loginController;

    public static final String PROVIDER_NAME = "provider";

    private KeyPair keyPair;

    private static final String ISSUER_URL = "http://localhost:8082/realms/platform-realm";

    private OAuth2ProviderSettingsUpdateDto providerSettings;

    String tokenValue;

    WireMockServer mockServer;

    String jwkSetJson;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, JsonProcessingException, JOSEException {
        mockServer = new WireMockServer(8082);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        mockServer
                .stubFor(WireMock
                        .get("/realms/platform-realm/.well-known/openid-configuration")
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(String.format("""
                                        {
                                          "issuer": "%s",
                                          "authorization_endpoint": "%s/protocol/openid-connect/auth",
                                          "token_endpoint": "%s/protocol/openid-connect/token",
                                          "jwks_uri": "%s/protocol/openid-connect/certs",
                                          "grant_types_supported": ["authorization_code", "implicit", "refresh_token"]
                                        }
                                        """, ISSUER_URL, ISSUER_URL, ISSUER_URL, ISSUER_URL))));

        jwkSetJson = "{\"keys\":[" + convertRSAPrivateKeyToJWK((RSAPublicKey) keyPair.getPublic()) + "]}";

        mockServer
                .stubFor(WireMock
                        .get("/realms/platform-realm/protocol/openid-connect/certs")
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(jwkSetJson)));

        mockServer
                .stubFor(WireMock
                        .get("/api/oauth2/provider/jwkSet")
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(jwkSetJson)));

        providerSettings = new OAuth2ProviderSettingsUpdateDto();
        providerSettings.setIssuerUrl(ISSUER_URL);
        providerSettings.setJwkSetUrl(ISSUER_URL + "/protocol/openid-connect/certs");
        providerSettings.setClientId("test-client");
        providerSettings.setClientSecret("test-client-secret");
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);

        tokenValue = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 3600 * 1000, ISSUER_URL, AUDIENCE, "");

    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
        AuthenticationSnapshotRequestHolder.clear();
    }

    @Test
    void testAuthenticationOnlyIfNeeded() {
        Assertions.assertNull(jwtDecoder.decode(tokenValue));

        AuthenticationInfo authenticationInfo = AuthenticationInfo.getAnonymousAuthenticationInfo();
        PlatformAnonymousToken authentication = new PlatformAnonymousToken(UUID.randomUUID().toString(),
                authenticationInfo, authenticationInfo.getAuthorities());
        SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
        emptyContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(emptyContext);
        Assertions.assertNotNull(jwtDecoder.decode(tokenValue));

        authentication.setAccessingPermitAllEndpoint(true);
        Assertions.assertNull(jwtDecoder.decode(tokenValue));
    }

    @Test
    void publishesSnapshotUsedForValidation() {
        SecurityContextHolder.clearContext();
        AuthenticationSnapshotRequestHolder.clear();

        Jwt jwt = jwtDecoder.decode(tokenValue);

        // the settings the token was validated against are handed to the identity resolution that follows
        AuthenticationSettingsSnapshot published = AuthenticationSnapshotRequestHolder.get();
        Assertions.assertNotNull(jwt);
        Assertions.assertNotNull(published);
        Assertions
                .assertEquals(ISSUER_URL, published.settings().getOAuth2Providers().get(PROVIDER_NAME).getIssuerUrl());
    }

    @Test
    void testNullIssuer() throws JOSEException {
        SecurityContextHolder.clearContext();
        String token = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, null, null, null);
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(token));
        Assertions.assertTrue(exception.getMessage().contains("Issuer URI is not present in JWT."));
    }

    @Test
    void testNoOauth2Provider() {
        settingService.removeOAuth2Provider(PROVIDER_NAME);
        SecurityContextHolder.clearContext();
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("No OAuth2 Provider with issuer URI"));
    }

    @Test
    void throwsValidationException_whenReadingMalformedProviderSettings() {
        // given
        corruptStoredProviderSettings();

        // when
        ThrowingCallable read = () -> settingService.getOAuth2ProviderSettings(PROVIDER_NAME, false);

        // then
        assertThatThrownBy(read).isInstanceOf(ValidationException.class);
    }

    @Test
    void throwsValidationException_whenUpdatingMalformedProviderSettings() {
        // given
        corruptStoredProviderSettings();
        providerSettings.setClientSecret(null);

        // when
        ThrowingCallable update = () -> settingService
                .updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);

        // then
        assertThatThrownBy(update).isInstanceOf(ValidationException.class);
    }

    @Test
    void testJwtDecoderOnValidTokenWithoutAudiences() throws JOSEException {
        SecurityContextHolder.clearContext();
        Assertions.assertInstanceOf(Jwt.class, jwtDecoder.decode(tokenValue));

        String almostExpiredToken = OAuth2TestUtil
                .createJwtTokenValue(keyPair.getPrivate(), 1, ISSUER_URL, AUDIENCE, "");
        // Test if 30 s skew is added to the time and therefore the token should be successfully validated
        Assertions.assertInstanceOf(Jwt.class, jwtDecoder.decode(almostExpiredToken));
    }

    @Test
    void throwsExpired_whenTokenIsExpiredAndSkewIsZero() throws Exception {
        // given
        providerSettings.setSkew(0);
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);
        SecurityContextHolder.clearContext();
        var expiredToken = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, ISSUER_URL, AUDIENCE, "");

        // when
        ThrowingCallable decode = () -> jwtDecoder.decode(expiredToken);

        // then
        assertThatThrownBy(decode)
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasMessageContaining("Jwt expired");
    }

    @Test
    void decodesToken_whenAudienceIsAccepted() {
        // given
        providerSettings.setAudiences(List.of(AUDIENCE));
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);
        SecurityContextHolder.clearContext();

        // when
        Jwt decoded = jwtDecoder.decode(tokenValue);

        // then
        assertThat(decoded).isInstanceOf(Jwt.class);
    }

    @Test
    void throwsInvalidAudience_whenTokenAudienceIsNotAccepted() {
        // given
        providerSettings.setAudiences(List.of("different-audience"));
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);
        SecurityContextHolder.clearContext();

        // when
        ThrowingCallable decode = () -> jwtDecoder.decode(tokenValue);

        // then
        assertThatThrownBy(decode)
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasMessageContaining("The aud claim is not valid");
    }

    @Test
    void servesEmbeddedJwkSet_whenProviderHoldsOneInsteadOfAUrl() {
        // given
        storeEmbeddedJwkSet();

        // when
        ResponseEntity<String> response = loginController.getJwkSet(PROVIDER_NAME);

        // then
        assertThat(response.getBody()).isEqualTo(jwkSetJson);
    }

    @Test
    void decodesToken_whenProviderHoldsAnEmbeddedJwkSet() {
        // given
        storeEmbeddedJwkSet();
        SecurityContextHolder.clearContext();

        // when
        Jwt decoded = jwtDecoder.decode(tokenValue);

        // then
        assertThat(decoded).isInstanceOf(Jwt.class);
    }

    @Test
    void testInvalidJwk() throws NoSuchAlgorithmException, JsonProcessingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair invalidKeyPair = generator.generateKeyPair();

        String invalidJwkSetJson = "{\"keys\":[" + convertRSAPrivateKeyToJWK((RSAPublicKey) invalidKeyPair.getPublic())
                + "]}";

        mockServer
                .stubFor(WireMock
                        .get("/realms/platform-realm/protocol/openid-connect/certs")
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(invalidJwkSetJson)));

        SecurityContextHolder.clearContext();
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("Invalid signature"));
    }

    @Test
    void throwsAuthenticationException_whenJwkSetUrlIsUnreachable() {
        // given
        providerSettings.setJwkSetUrl(ISSUER_URL + "/protocol/openid-connect/certs");
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);
        mockServer.resetAll();
        SecurityContextHolder.clearContext();

        // when
        ThrowingCallable decode = () -> jwtDecoder.decode(tokenValue);

        // then
        assertThatThrownBy(decode).isInstanceOf(PlatformAuthenticationException.class);
    }

    @Test
    void testUnsignedJwt() {
        SecurityContextHolder.clearContext();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("your-subject")
                .audience(AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour
                .issuer(ISSUER_URL)
                .build();

        tokenValue = new PlainJWT(claimsSet).serialize();
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("Token is not an instance of Signed JWT"));
    }

    private void corruptStoredProviderSettings() {
        Setting setting = settingRepository
                .findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION,
                        SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), PROVIDER_NAME);
        setting.setValue("WRONG-DATA");
        settingRepository.save(setting);
    }

    private void storeEmbeddedJwkSet() {
        providerSettings.setJwkSetUrl(null);
        providerSettings.setJwkSet(Base64.getEncoder().encodeToString(jwkSetJson.getBytes()));
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, null, providerSettings);
    }

    private String convertRSAPrivateKeyToJWK(RSAPublicKey publicKey) throws JsonProcessingException {
        BigInteger modulus = publicKey.getModulus();
        BigInteger publicExponent = publicKey.getPublicExponent();

        String n = Base64.getEncoder().encodeToString(modulus.toByteArray());
        String e = Base64.getEncoder().encodeToString(publicExponent.toByteArray());

        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", n);
        jwk.put("e", e);
        jwk.put("alg", "RS256");
        jwk.put("use", "sig");

        return new ObjectMapper().writeValueAsString(jwk);
    }

}
