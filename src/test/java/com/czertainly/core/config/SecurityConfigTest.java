package com.czertainly.core.config;

import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.core.security.oauth2.OAuth2TestUtil;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.*;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.*;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@AutoConfigureMockMvc
@SpringBootTest
class SecurityConfigTest extends BaseSpringBootTestNoAuth {

    @Autowired
    MockMvc mvc;

    @MockitoBean
    JwtDecoder jwtDecoder;

    @Autowired
    SettingsCache settingsCache;

    @MockitoBean
    private JdbcIndexedSessionRepository sessionRepository;

    @MockitoBean
    private GenericConversionService springSessionConversionService;

    @MockitoBean
    public SessionRepositoryFilter springSessionRepositoryFilter;


    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10003");
        registry.add("server.servlet.context-path", () -> "");
    }

    static final String CERTIFICATE_USER_USERNAME = "certificate-user";
    static final String CERTIFICATE_HEADER_VALUE = "certificate";
    static final String TOKEN_USER_USERNAME = "token-user";

    Jwt mockJwt;
    String tokenValue;
    String tokenHeaderValue;
    WireMockServer mockServer;
    PrivateKey privateKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, JOSEException, ServletException, IOException {
        Mockito.doAnswer(invocation -> {
            ServletRequest request = invocation.getArgument(0);
            ServletResponse response = invocation.getArgument(1);
            FilterChain filterChain = invocation.getArgument(2);
            filterChain.doFilter(request, response);
            return null;
        }).when(springSessionRepositoryFilter).doFilter(Mockito.any(), Mockito.any(), Mockito.any());

        mockServer = new WireMockServer(10003);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        String certificateUserUuid = UUID.randomUUID().toString();
        addAuthPostStub(CERTIFICATE_HEADER_VALUE, certificateUserUuid, CERTIFICATE_USER_USERNAME);
        addAuthPostStub("localhost", "", "");
        addAuthGetSub(certificateUserUuid, CERTIFICATE_USER_USERNAME);

        String tokenUserUuid = UUID.randomUUID().toString();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        tokenValue = OAuth2TestUtil.createJwtTokenValue(privateKey, null, "http://issuer", null, TOKEN_USER_USERNAME);
        tokenHeaderValue = "Bearer " + tokenValue;
        mockJwt = Jwt.withTokenValue(tokenValue)
                .header("alg", "RS256")
                .claim("username", TOKEN_USER_USERNAME)
                .issuer("http://issuer")
                .build();
        addAuthPostStub("{\"iss\":\"http://issuer\",\"" + OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME + "\":\"token-user\"}", tokenUserUuid, TOKEN_USER_USERNAME);
        addAuthGetSub(tokenUserUuid, TOKEN_USER_USERNAME);

    }

    @AfterEach
    void afterEach() {
        mockServer.stop();
    }

    @Test
    void authorizeUsingCertificate() throws Exception {
        MvcResult result = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile")
                .header("X-APP-CERTIFICATE", CERTIFICATE_HEADER_VALUE)).andReturn();
        Assertions.assertTrue(result.getResponse().getContentAsString().contains(CERTIFICATE_USER_USERNAME));
    }

    @Test
    void authorizeProtocolEndpoint() throws Exception {
        mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/protocols/acme/raProfile/RA Profile/directory")).andExpect(status().isBadRequest());
    }

    @Test
    void authorizeUsingJwtToken() throws Exception {
        cacheProviderSettings(null, "http://issuer");
        Mockito.when(jwtDecoder.decode(tokenValue)).thenReturn(mockJwt);
        MvcResult result = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile")
                .header("Authorization", tokenHeaderValue)).andReturn();
        Assertions.assertTrue(result.getResponse().getContentAsString().contains(TOKEN_USER_USERNAME));

    }

    @Test
    void authorizeWithCertificateAndToken() throws Exception {
        Mockito.when(jwtDecoder.decode(tokenValue)).thenReturn(null);
        MvcResult result = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile")
                .header("X-APP-CERTIFICATE", CERTIFICATE_HEADER_VALUE)
                .header("Authorization", tokenHeaderValue)).andReturn();
        Assertions.assertTrue(result.getResponse().getContentAsString().contains(CERTIFICATE_USER_USERNAME));
    }

    @Test
    void testPermitAllEndpoint() throws Exception {
        mvc.perform(post(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/connector/register").content("""
                {
                    "name": "name",
                    "url": "http://network-discovery-provicer:8080",
                    "authType": "none"
                }""").contentType(MediaType.APPLICATION_JSON)).andExpect(status().is5xxServerError());
    }

    @Test
    void testOauth2Login() throws Exception {
        String userUuid = UUID.randomUUID().toString();
        String username = "login-user";
        addAuthPostStub("{\"sub\":\"user\",\"username\":\"%s\"}".formatted(username), userUuid, username);
        addAuthGetSub(userUuid, username);

        String oauth2Token = OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, username);
        cacheProviderSettings(null);
        MockHttpSession mockHttpSession = new MockHttpSession();
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, oauth2Token, Instant.now(), Instant.MAX);
        mockHttpSession.setAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE, oauth2AccessToken);
        MvcResult result = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile").with(oidcLogin()).session(mockHttpSession)).andReturn();
        Assertions.assertTrue(result.getResponse().getContentAsString().contains(username));

        String idTokenUsername = "id-token-username";
        String idTokenUuid = UUID.randomUUID().toString();
        addAuthPostStub("{\"sub\":\"user\",\"username\":\"%s\"}".formatted(idTokenUsername), idTokenUuid, idTokenUsername);
        addAuthGetSub(idTokenUuid, idTokenUsername);
        result = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile").with(oidcLogin().idToken(token -> token.claim(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, idTokenUsername))).session(mockHttpSession)).andReturn();
        Assertions.assertTrue(result.getResponse().getContentAsString().contains(idTokenUsername));

        cacheProviderSettings("http://localhost:" + mockServer.port() + "/userinfo");
        String userInfoUsername = "user-info-username";
        String userInfoUuid = UUID.randomUUID().toString();
        addUserInfoStub(userInfoUsername);
        addAuthPostStub("{\"sub\":\"user\",\"username\":\"%s\"}".formatted(userInfoUsername), userInfoUuid, userInfoUsername);
        addAuthGetSub(userInfoUuid, userInfoUsername);
        result = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile").with(oidcLogin()).session(mockHttpSession)).andReturn();
        Assertions.assertTrue(result.getResponse().getContentAsString().contains(userInfoUsername));
    }

    @Test
    void testOAuth2LoginRefreshingToken() throws Exception {
        cacheProviderSettings(null);
        String oauth2Token = OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, "oldUsername");
        OAuth2AccessToken oauth2AccessTokenToRefresh = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, oauth2Token, Instant.now(), Instant.now().plusMillis(1));
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE, oauth2AccessTokenToRefresh);
        OAuth2RefreshToken oAuth2RefreshToken = new OAuth2RefreshToken("random", Instant.now());
        mockHttpSession.setAttribute(OAuth2Constants.REFRESH_TOKEN_SESSION_ATTRIBUTE, oAuth2RefreshToken);
        String refreshedUserName = "refreshed-user";
        String refreshedUserUuid = UUID.randomUUID().toString();
        addAuthPostStub("{\"iss\":\"newInfo\",\"sub\":\"user\",\"username\":\"%s\"}".formatted(refreshedUserName), refreshedUserUuid, refreshedUserName);
        addAuthGetSub(refreshedUserUuid, refreshedUserName);
        addTokenEndpointStub(OAuth2TestUtil.createJwtTokenValue(privateKey, null, "newInfo", null, refreshedUserName));
        MvcResult resultRefresh = mvc.perform(get(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/v1/auth/profile").with(oidcLogin().idToken(token -> token.claim(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, refreshedUserName))).session(mockHttpSession)).andReturn();
        Assertions.assertTrue(resultRefresh.getResponse().getContentAsString().contains(refreshedUserName));
    }

    void cacheProviderSettings(String userInfoUrl) {
        cacheProviderSettings(userInfoUrl, null);
    }

    void cacheProviderSettings(String userInfoUrl, String issuerUrl) {
        AuthenticationSettingsDto authenticationSettingsDto = OAuth2TestUtil.getAuthenticationSettings(userInfoUrl, mockServer.port(), new ArrayList<>(), issuerUrl);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, authenticationSettingsDto);
    }

    void addAuthPostStub(String requestBody, String userUuid, String username) {
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/auth"))
                .withRequestBody(WireMock.containing(requestBody))
                .willReturn(
                        WireMock.okJson(String.format("""        
                                {
                                  "authenticated": true,
                                  "data": {
                                    "user": {
                                      "uuid": "%s",
                                      "username": "%s"
                                    },
                                    "roles": [
                                      {
                                        "name": "superadmin"
                                      }
                                    ],
                                    "permissions": {
                                      "allowAllResources": true,
                                      "resources": []
                                    }
                                  }
                                }
                                """, userUuid, username)
                        )
                ));
    }

    void addAuthGetSub(String userUuid, String username) {
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/" + userUuid)).willReturn(
                WireMock.okJson(String.format("{ \"username\": \"%s\", \"roles\": [{\"name\": \"superadmin\"}]}", username))
        ));
    }

    void addTokenEndpointStub(String tokenValue) {
        String responseJson = """
                {
                  "access_token":"%s",
                  "token_type":"Bearer",
                  "expires_in":3600,
                  "refresh_token":"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
                  "scope":"create"
                }
                """.formatted(tokenValue);
        mockServer.stubFor(WireMock.post("/token").willReturn(WireMock.okJson(responseJson).withHeader("contentType", "application/json")));
    }

    void addUserInfoStub(String userInfoUsername) {
        mockServer.stubFor(WireMock.get("/userinfo").willReturn(
                WireMock.aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                "username": "%s"
                                }
                                """.formatted(userInfoUsername))
        ));
    }

}
