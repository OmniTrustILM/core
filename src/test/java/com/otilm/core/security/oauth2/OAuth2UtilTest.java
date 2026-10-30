package com.otilm.core.security.oauth2;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.logging.LogRedaction;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.OAuth2Constants;
import com.otilm.core.util.OAuth2Util;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.session.Session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2UtilTest {

    @Test
    void testValidateAudiences() throws NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        OAuth2ProviderSettingsDto providerSettingsDto = new OAuth2ProviderSettingsDto();
        OAuth2AccessToken accessTokenCorrectAudience = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, null, "expected", ""), Instant.now(),
                Instant.now().plusMillis(200));
        OAuth2AccessToken accessTokenIncorrectAudience = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 1, null, "unexpected", ""), Instant.now(),
                Instant.now().plusMillis(200));

        providerSettingsDto.setAudiences(List.of("expected"));
        Assertions
                .assertDoesNotThrow(
                        () -> OAuth2Util.validateAudiences(accessTokenCorrectAudience, providerSettingsDto));

        providerSettingsDto.setAudiences(List.of("expected", "other"));
        Assertions
                .assertDoesNotThrow(
                        () -> OAuth2Util.validateAudiences(accessTokenCorrectAudience, providerSettingsDto));

        Assertions
                .assertThrows(PlatformAuthenticationException.class,
                        () -> OAuth2Util.validateAudiences(accessTokenIncorrectAudience, providerSettingsDto));

        providerSettingsDto.setAudiences(new ArrayList<>());
        Assertions
                .assertDoesNotThrow(
                        () -> OAuth2Util.validateAudiences(accessTokenIncorrectAudience, providerSettingsDto));

    }

    @Test
    void validateAudiencesFailure_recordsTheAccessTokenWithoutItsSignature() throws Exception {
        // given - a signed access token whose audience does not match the provider's configured audiences
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().audience("other-audience").build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        String token = jwt.serialize();
        String[] parts = token.split("\\.");
        String unsignedToken = parts[0] + "." + parts[1];
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, Instant.now(),
                Instant.now().plusSeconds(300));
        OAuth2ProviderSettingsDto providerSettings = new OAuth2ProviderSettingsDto();
        providerSettings.setAudiences(List.of("expected-audience"));

        // when
        PlatformAuthenticationException e = Assertions
                .assertThrows(PlatformAuthenticationException.class,
                        () -> OAuth2Util.validateAudiences(accessToken, providerSettings));

        // then
        assertThat(e.getMessage()).contains(unsignedToken).doesNotContain(parts[2]);
    }

    @Test
    void validateAudiencesFailure_forAnOpaqueAccessToken_redactsIt() {
        // given - an access token that is not a JWT at all
        String opaqueToken = "opaque-access-token-value";
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, opaqueToken,
                Instant.now(), Instant.now().plusSeconds(300));
        OAuth2ProviderSettingsDto providerSettings = new OAuth2ProviderSettingsDto();

        // when
        PlatformAuthenticationException e = Assertions
                .assertThrows(PlatformAuthenticationException.class,
                        () -> OAuth2Util.validateAudiences(accessToken, providerSettings));

        // then
        assertThat(e.getMessage()).contains(LogRedaction.REDACTED).doesNotContain(opaqueToken);
    }

    @Test
    void getAllClaimsAvailableFailure_forAnOpaqueAccessToken_doesNotRecordItsRawValue() {
        // given - an access token that is not a JWT, and a provider with no user-info URL configured
        String opaqueToken = "opaque-access-token-value";
        OAuth2ProviderSettingsDto providerSettings = new OAuth2ProviderSettingsDto();
        providerSettings.setName("test");

        // when
        PlatformAuthenticationException e = Assertions
                .assertThrows(PlatformAuthenticationException.class,
                        () -> OAuth2Util.getAllClaimsAvailable(providerSettings, opaqueToken, null));

        // then
        assertThat(e.getMessage()).doesNotContain(opaqueToken);
    }

    @Test
    void testEndUserSession_SuccessfulLogout() {
        // Mocks
        Session session = mock(Session.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        OAuth2AuthenticationToken authToken = mock(OAuth2AuthenticationToken.class);
        DefaultOidcUser oidcUser = mock(DefaultOidcUser.class);
        AuthenticationSettingsDto authSettings = mock(AuthenticationSettingsDto.class);
        OAuth2ProviderSettingsDto providerSettings = mock(OAuth2ProviderSettingsDto.class);

        // Prepare session returns security context
        when(session.getAttribute("SPRING_SECURITY_CONTEXT")).thenReturn(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authToken);

        // Prepare token and provider mocks
        when(authToken.getAuthorizedClientRegistrationId()).thenReturn("test-client");
        when(authToken.getPrincipal()).thenReturn(oidcUser);
        when(authToken.getName()).thenReturn("my-user");
        when(oidcUser.getIdToken()).thenReturn(mock(org.springframework.security.oauth2.core.oidc.OidcIdToken.class));
        when(oidcUser.getIdToken().getTokenValue()).thenReturn("id-token-value");

        // Prepare AuthenticationSettingsDto and OAuth2ProviderSettingsDto
        WireMockServer mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("test-client", providerSettings);
        when(authSettings.getOAuth2Providers()).thenReturn(providers);
        when(providerSettings.getLogoutUrl()).thenReturn(LoopbackWireMock.url(mockServer));
        when(providerSettings.getName()).thenReturn("TestProvider");

        // Mock static SettingsCache
        try (MockedStatic<SettingsCache> settingsCacheMock = mockStatic(SettingsCache.class)) {
            settingsCacheMock
                    .when(() -> SettingsCache.getSettings(SettingsSection.AUTHENTICATION))
                    .thenReturn(authSettings);
            // Not mocked endpoint
            SecurityContext springSecurityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
            Assertions.assertDoesNotThrow(() -> OAuth2Util.endUserSession(springSecurityContext));

            WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/"))
                            .withQueryParam("id_token_hint", WireMock.matching(".*"))
                            .willReturn(WireMock.aResponse().withStatus(200)));
            // Mocked endpoint
            Assertions.assertDoesNotThrow(() -> OAuth2Util.endUserSession(springSecurityContext));

            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/"))
                            .withQueryParam("id_token_hint", WireMock.matching(".*"))
                            .willReturn(WireMock.aResponse().withStatus(500)));
            // Mocked endpoint 500
            Assertions.assertDoesNotThrow(() -> OAuth2Util.endUserSession(springSecurityContext));

            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/"))
                            .withQueryParam("id_token_hint", WireMock.matching(".*"))
                            .willReturn(WireMock.aResponse().withStatus(404)));
            // Mocked endpoint 404
            Assertions.assertDoesNotThrow(() -> OAuth2Util.endUserSession(springSecurityContext));
        }
        mockServer.stop();
    }

    @Test
    void testGetAllClaimsAvailable_UserInfoClaimsOverrideAccessTokenClaims()
            throws NoSuchAlgorithmException, JOSEException {
        String accessToken = createAccessToken("from-token");
        WireMockServer mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        try {
            WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/userinfo"))
                            .willReturn(WireMock
                                    .okJson("{\"%s\":\"from-userinfo\",\"email\":\"user@example.com\"}"
                                            .formatted(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME))));

            Map<String, Object> claims = OAuth2Util
                    .getAllClaimsAvailable(providerWithUserInfoUrl(LoopbackWireMock.url(mockServer) + "/userinfo"),
                            accessToken, null);

            Assertions.assertEquals("from-userinfo", claims.get(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME));
            Assertions.assertEquals("user@example.com", claims.get("email"));
            mockServer
                    .verify(WireMock.exactly(1),
                            WireMock
                                    .getRequestedFor(WireMock.urlPathEqualTo("/userinfo"))
                                    .withHeader("Authorization", WireMock.equalTo("Bearer " + accessToken))
                                    .withHeader("Accept", WireMock.containing("application/json")));
        } finally {
            mockServer.stop();
        }
    }

    @Test
    void testGetAllClaimsAvailable_UserInfoFailureFallsBackToAccessTokenClaims()
            throws NoSuchAlgorithmException, JOSEException {
        String accessToken = createAccessToken("from-token");
        WireMockServer mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        try {
            WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
            OAuth2ProviderSettingsDto provider = providerWithUserInfoUrl(
                    LoopbackWireMock.url(mockServer) + "/userinfo");

            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/userinfo"))
                            .willReturn(WireMock.aResponse().withStatus(500)));
            Map<String, Object> claims = OAuth2Util.getAllClaimsAvailable(provider, accessToken, null);
            Assertions.assertEquals("from-token", claims.get(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME));
            mockServer.verify(WireMock.exactly(1), WireMock.getRequestedFor(WireMock.urlPathEqualTo("/userinfo")));

            mockServer.resetRequests();
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/userinfo"))
                            .willReturn(WireMock
                                    .aResponse()
                                    .withStatus(400)
                                    .withHeader("Content-Type", "application/json")
                                    .withBody("{\"error\":\"invalid_token\"}")));
            claims = OAuth2Util.getAllClaimsAvailable(provider, accessToken, null);
            Assertions.assertEquals("from-token", claims.get(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME));
            mockServer.verify(WireMock.exactly(1), WireMock.getRequestedFor(WireMock.urlPathEqualTo("/userinfo")));
        } finally {
            mockServer.stop();
        }
    }

    private static String createAccessToken(String username) throws NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 60000, "http://issuer", "audience", username);
    }

    private static OAuth2ProviderSettingsDto providerWithUserInfoUrl(String userInfoUrl) {
        OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
        provider.setName("test");
        provider.setUserInfoUrl(userInfoUrl);
        return provider;
    }

}
