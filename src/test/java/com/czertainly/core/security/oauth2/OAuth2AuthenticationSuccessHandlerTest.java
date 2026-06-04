package com.czertainly.core.security.oauth2;

import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.core.auth.oauth2.CzertainlyAuthenticationSuccessHandler;
import com.czertainly.core.auth.oauth2.CzertainlyClientRegistrationRepository;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.OAuth2Constants;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SpringBootTest
class OAuth2AuthenticationSuccessHandlerTest {

    @MockitoBean
    OAuth2AuthorizedClientService clientService;

    @Autowired
    CzertainlyAuthenticationSuccessHandler successHandler;

    @Autowired
    SettingsCache settingsCache;

    @Autowired
    CzertainlyClientRegistrationRepository clientRegistrationRepository;

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
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, OAuth2TestUtil.getAuthenticationSettings(null, 0, new ArrayList<>(), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, "username"), Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        Mockito.when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, "username");
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Assertions.assertDoesNotThrow(() -> successHandler.onAuthenticationSuccess(mockHttpServletRequest, new MockHttpServletResponse(), authenticationToken));
    }

    @Test
    void testFailOnValidatingAudiences() throws JOSEException {
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, OAuth2TestUtil.getAuthenticationSettings(null, 0, List.of("audience"), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, "username"), Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        Mockito.when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, "username");
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Exception exception = Assertions.assertThrows(CzertainlyAuthenticationException.class, () -> successHandler.onAuthenticationSuccess(mockHttpServletRequest, mockHttpServletResponse, authenticationToken));
        Assertions.assertTrue(exception.getMessage().contains("do not match any of audiences"));
    }

    @Test
    void testFailOnValidatingUsername() throws JOSEException {
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, OAuth2TestUtil.getAuthenticationSettings(null, 0, new ArrayList<>(), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, null), Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        Mockito.when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Exception exception = Assertions.assertThrows(CzertainlyAuthenticationException.class, () -> successHandler.onAuthenticationSuccess(mockHttpServletRequest, mockHttpServletResponse, authenticationToken));
        Assertions.assertTrue(exception.getMessage().contains("username"));
    }


    @Test
    void testFailOnMissingProvider() throws JOSEException {
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, OAuth2TestUtil.getAuthenticationSettings(null, 0, new ArrayList<>(), null));
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, OAuth2TestUtil.createJwtTokenValue(privateKey, null, null, null, null), Instant.now(), Instant.MAX);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistrationRepository.findByRegistrationId("test"), "name", oauth2AccessToken);
        Mockito.when(clientService.loadAuthorizedClient("test", "sub")).thenReturn(authorizedClient);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("sub", "sub");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusMillis(100), idTokenClaims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(null, idToken);
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oidcUser, null, "test");
        Exception exception = Assertions.assertThrows(CzertainlyAuthenticationException.class, () -> successHandler.onAuthenticationSuccess(mockHttpServletRequest, mockHttpServletResponse, authenticationToken));
        Assertions.assertTrue(exception.getMessage().contains("Unknown OAuth2 Provider with name"));
    }
}
