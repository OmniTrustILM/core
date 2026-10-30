package com.otilm.core.integration.security.oauth2;

import com.nimbusds.jose.JOSEException;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.core.auth.oauth2.PlatformAuthenticationSuccessHandler;
import com.otilm.core.auth.oauth2.PlatformClientRegistrationRepository;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.oauth2.OAuth2TestUtil;
import com.otilm.core.service.AuditLogExternalService;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Constants;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
class OAuth2AuthenticationSuccessHandlerITest {

    @MockitoBean
    OAuth2AuthorizedClientService clientService;

    @MockitoBean
    AuditLogInternalService auditLogService;

    @MockitoBean
    AuditLogExternalService auditLogExternalService;

    @Autowired
    PlatformAuthenticationSuccessHandler successHandler;

    @Autowired
    SettingsCache settingsCache;

    @Autowired
    PlatformClientRegistrationRepository clientRegistrationRepository;

    PrivateKey privateKey;
    MockHttpServletRequest mockHttpServletRequest;
    MockHttpServletResponse mockHttpServletResponse;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        mockHttpServletRequest = new MockHttpServletRequest();
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE, "/redirect");
        mockHttpServletRequest.setSession(mockHttpSession);
        mockHttpServletResponse = new MockHttpServletResponse();
    }

    @Test
    void testSuccessfulAuthentication() throws JOSEException {
        settingsCache
                .cacheSettings(SettingsSection.AUTHENTICATION,
                        OAuth2TestUtil.getAuthenticationSettings(null, 0, new ArrayList<>(), null));
        String accessTokenValue = OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, "username");
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                accessTokenValue, Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, "username");
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Assertions
                .assertDoesNotThrow(() -> successHandler
                        .onAuthenticationSuccess(mockHttpServletRequest, new MockHttpServletResponse(),
                                authenticationToken));

        // a successful login is recorded without the live access token's signature
        String[] parts = accessTokenValue.split("\\.");
        verify(auditLogService)
                .logAuthentication(eq(Operation.LOGIN), eq(OperationResult.SUCCESS), isNull(),
                        eq(parts[0] + "." + parts[1]));
    }

    @Test
    void testFailOnValidatingAudiences() throws JOSEException {
        settingsCache
                .cacheSettings(SettingsSection.AUTHENTICATION,
                        OAuth2TestUtil.getAuthenticationSettings(null, 0, List.of("audience"), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, "username"), Instant.now(),
                Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, "username");
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> successHandler
                        .onAuthenticationSuccess(mockHttpServletRequest, mockHttpServletResponse, authenticationToken));
        Assertions.assertTrue(exception.getMessage().contains("do not match any of audiences"));
    }

    @Test
    void testFailOnValidatingUsername() throws JOSEException {
        settingsCache
                .cacheSettings(SettingsSection.AUTHENTICATION,
                        OAuth2TestUtil.getAuthenticationSettings(null, 0, new ArrayList<>(), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, null), Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> successHandler
                        .onAuthenticationSuccess(mockHttpServletRequest, mockHttpServletResponse, authenticationToken));
        Assertions.assertTrue(exception.getMessage().contains("username"));
    }

    @Test
    void testFailOnMissingProvider() throws JOSEException {
        settingsCache
                .cacheSettings(SettingsSection.AUTHENTICATION,
                        OAuth2TestUtil.getAuthenticationSettings(null, 0, new ArrayList<>(), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, null), Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Exception exception = Assertions
                .assertThrows(PlatformAuthenticationException.class, () -> successHandler
                        .onAuthenticationSuccess(mockHttpServletRequest, mockHttpServletResponse, authenticationToken));
        Assertions.assertTrue(exception.getMessage().contains("Unknown OAuth2 Provider with name"));
    }
}
