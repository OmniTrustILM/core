package com.otilm.core.security.oauth2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.core.auth.oauth2.LoginController;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.security.authn.PlatformAnonymousToken;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.SettingService;
import com.otilm.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;

@SpringBootTest
class JwtDecoderTest extends BaseSpringBootTest {

    public static final String AUDIENCE = "your-audience";
    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private SettingService settingService;

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

        mockServer.stubFor(WireMock.get("/realms/platform-realm/.well-known/openid-configuration")
                .willReturn(aResponse().withStatus(200)
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

        mockServer.stubFor(WireMock.get("/realms/platform-realm/protocol/openid-connect/certs")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwkSetJson)));

        mockServer.stubFor(WireMock.get("/api/oauth2/provider/jwkSet")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwkSetJson)));


        providerSettings = new OAuth2ProviderSettingsUpdateDto();
        providerSettings.setIssuerUrl(ISSUER_URL);
        providerSettings.setJwkSetUrl(ISSUER_URL + "/protocol/openid-connect/certs");
        providerSettings.setClientId("test-client");
        providerSettings.setClientSecret("test-client-secret");
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings);

        tokenValue = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 3600 * 1000, ISSUER_URL, AUDIENCE, "");

    }

    @AfterEach
    void stopServer() {
        mockServer.stop();
    }

    @Test
    void testAuthenticationOnlyIfNeeded() {
        Assertions.assertNull(jwtDecoder.decode(tokenValue));

        AuthenticationInfo authenticationInfo = AuthenticationInfo.getAnonymousAuthenticationInfo();
        PlatformAnonymousToken authentication = new PlatformAnonymousToken(UUID.randomUUID().toString(), authenticationInfo, authenticationInfo.getAuthorities());
        SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
        emptyContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(emptyContext);
        Assertions.assertNotNull(jwtDecoder.decode(tokenValue));

        authentication.setAccessingPermitAllEndpoint(true);
        Assertions.assertNull(jwtDecoder.decode(tokenValue));
    }

    @Test
    void testNullIssuer() throws JOSEException {
        SecurityContextHolder.clearContext();
        String token = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, null, null, null);
        Exception exception = Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(token));
        Assertions.assertTrue(exception.getMessage().contains("Issuer URI is not present in JWT."));
    }

    @Test
    void testNoOauth2Provider() {
        settingService.removeOAuth2Provider(PROVIDER_NAME);
        SecurityContextHolder.clearContext();
        Exception exception = Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("No OAuth2 Provider with issuer URI"));
    }

    @Test
    void testMalformedOAuth2ProviderSettings() {
        Setting setting = settingRepository.findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), PROVIDER_NAME);
        setting.setValue("WRONG-DATA");
        settingRepository.save(setting);

        providerSettings.setClientSecret(null);
        Assertions.assertThrows(ValidationException.class, () -> settingService.getOAuth2ProviderSettings(PROVIDER_NAME, false));
        Assertions.assertThrows(ValidationException.class, () -> settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings));
    }

    @Test
    void testJwtDecoderOnValidTokenWithoutAudiences() throws JOSEException {
        SecurityContextHolder.clearContext();
        Assertions.assertInstanceOf(Jwt.class, jwtDecoder.decode(tokenValue));

        String almostExpiredToken = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, ISSUER_URL, AUDIENCE, "");
        // Test if 30 s skew is added to the time and therefore the token should be successfully validated
        Assertions.assertInstanceOf(Jwt.class, jwtDecoder.decode(almostExpiredToken));
    }

    @Test
    void testJwtDecoderOnExpiredTokenWithoutAudiences() throws JOSEException {
        providerSettings.setSkew(0);
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings);

        SecurityContextHolder.clearContext();
        String expiredToken = OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, ISSUER_URL, AUDIENCE, "");
        Exception exception = Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(expiredToken));
        Assertions.assertTrue(exception.getMessage().contains("Jwt expired"));
    }

    @Test
    void testJwtDecoderOnTokenWithValidAudiences() {
        providerSettings.setAudiences(List.of(AUDIENCE));
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings);

        SecurityContextHolder.clearContext();
        Assertions.assertInstanceOf(Jwt.class, jwtDecoder.decode(tokenValue));
    }

    @Test
    void testJwtDecoderOnTokenWithInvalidAudiences() {
        providerSettings.setAudiences(List.of("different-audience"));
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings);
        SecurityContextHolder.clearContext();
        Exception exception = Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("The aud claim is not valid"));
    }

    @Test
    void testJwkSetFromInput() {
        providerSettings.setJwkSetUrl(null);
        providerSettings.setJwkSet(Base64.getEncoder().encodeToString(jwkSetJson.getBytes()));
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings);
        ResponseEntity<String> response = loginController.getJwkSet(PROVIDER_NAME);
        Assertions.assertEquals(jwkSetJson, response.getBody());

        SecurityContextHolder.clearContext();
        Assertions.assertInstanceOf(Jwt.class, jwtDecoder.decode(tokenValue));
    }

    @Test
    void testInvalidJwk() throws NoSuchAlgorithmException, JsonProcessingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair invalidKeyPair = generator.generateKeyPair();

        String invalidJwkSetJson = "{\"keys\":[" + convertRSAPrivateKeyToJWK((RSAPublicKey) invalidKeyPair.getPublic()) + "]}";

        mockServer.stubFor(WireMock.get("/realms/platform-realm/protocol/openid-connect/certs")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(invalidJwkSetJson)));

        SecurityContextHolder.clearContext();
        Exception exception = Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("Invalid signature"));
    }

    @Test
    void testUnreachableJwkUrl() {
        providerSettings.setJwkSetUrl(ISSUER_URL + "/protocol/openid-connect/certs");
        settingService.updateOAuth2ProviderSettings(PROVIDER_NAME, providerSettings);

        mockServer.resetAll();
        SecurityContextHolder.clearContext();
        Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
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
        Exception exception = Assertions.assertThrows(PlatformAuthenticationException.class, () -> jwtDecoder.decode(tokenValue));
        Assertions.assertTrue(exception.getMessage().contains("Token is not an instance of Signed JWT"));
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
