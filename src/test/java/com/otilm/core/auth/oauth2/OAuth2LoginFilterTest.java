package com.otilm.core.auth.oauth2;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Constants;
import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2LoginFilterTest {

    private static final String REGISTRATION_ID = "probe-idp";

    private final AuditLogInternalService auditLogService = mock(AuditLogInternalService.class);
    private final PlatformClientRegistrationRepository clientRegistrationRepository = mock(
            PlatformClientRegistrationRepository.class);
    private final OAuth2AuthorizedClientProvider authorizedClientProvider = mock(OAuth2AuthorizedClientProvider.class);
    private final OAuth2LoginFilter filter = new OAuth2LoginFilter();
    private final Logger filterLogger = (Logger) LoggerFactory.getLogger(OAuth2LoginFilter.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private AuthenticationSettingsDto previousSettings;
    private String accessToken;
    private String unsignedAccessToken;
    private String signature;

    @BeforeEach
    void setUp() throws Exception {
        filter.setAuditLogService(auditLogService);
        filter.setClientRegistrationRepository(clientRegistrationRepository);
        filter.setAuthorizedClientProvider(authorizedClientProvider);
        logged.start();
        filterLogger.addAppender(logged);
        previousSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        DefaultOAuth2User user = new DefaultOAuth2User(List.of(), Map.of("sub", "alice"), "sub");
        SecurityContextHolder
                .getContext()
                .setAuthentication(new OAuth2AuthenticationToken(user, List.of(), REGISTRATION_ID));
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().issuer("https://idp.example").subject("alice").build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        accessToken = jwt.serialize();
        String[] parts = accessToken.split("\\.");
        unsignedAccessToken = parts[0] + "." + parts[1];
        signature = parts[2];
    }

    @AfterEach
    void restore() {
        filterLogger.detachAppender(logged);
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, previousSettings);
        SecurityContextHolder.clearContext();
    }

    @Test
    void theAccessTokenOfAnUnknownProvider_isRecordedWithoutItsSignature() {
        // given - no provider is configured under the session's registration
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
        MockHttpServletRequest request = requestHolding(Instant.now().plusSeconds(300));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        // when
        assertThrows(PlatformAuthenticationException.class, () -> filter.doFilter(request, response, chain));

        // then
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), anyString(),
                        eq(unsignedAccessToken));
    }

    @Test
    void aFailedRefresh_isRecordedWithoutTheAccessTokensSignature() throws Exception {
        // when - the access token has expired and the provider refuses to refresh it
        MockHttpServletResponse response = refreshRefusedWith(new OAuth2Error("invalid_grant"));

        // then
        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), message.capture(),
                        eq(unsignedAccessToken));
        assertThat(message.getValue()).contains(unsignedAccessToken).doesNotContain(signature);
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void aFailedRefresh_isRecordedLoggedAndAnsweredWithOnlyTheProvidersErrorCode() throws Exception {
        // when - the provider's error description echoes the refresh request, refresh token included
        MockHttpServletResponse response = refreshRefusedWith(
                new OAuth2Error("invalid_grant", "grant_type=refresh_token&refresh_token=refresh-token-value", null));

        // then
        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), message.capture(),
                        eq(unsignedAccessToken));
        assertThat(message.getValue()).contains("invalid_grant").doesNotContain("refresh-token-value");
        assertThat(logged.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .contains("invalid_grant")
                .noneMatch(line -> line.contains("refresh-token-value"));
        assertThat(response.getErrorMessage()).isEqualTo("invalid_grant");
    }

    @Test
    void aRefreshWithoutARefreshToken_isRecordedAndAnsweredWithCoresOwnMessage() throws Exception {
        // given - the access token has expired and the session holds no refresh token
        configureProvider();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        filter.doFilter(requestHolding(Instant.now().minusSeconds(60)), response, mock(FilterChain.class));

        // then
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE),
                        contains("Refresh token is not available"), eq(unsignedAccessToken));
        assertThat(response.getErrorMessage()).startsWith("Refresh token is not available");
    }

    @Test
    void anAudienceMismatch_isRecordedWithoutTheAccessTokensSignature() throws Exception {
        // given - the initial access token has expired, its refresh succeeds, but the refreshed token's audience
        // does not match the provider's configured audience
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        OAuth2ProviderSettingsDto providerSettings = new OAuth2ProviderSettingsDto();
        providerSettings.setAudiences(List.of("expected-audience"));
        settings.getOAuth2Providers().put(REGISTRATION_ID, providerSettings);
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, settings);
        ClientRegistration clientRegistration = clientRegistration();
        when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(clientRegistration);

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().audience("other-audience").build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        String mismatchedAudienceToken = jwt.serialize();
        String[] parts = mismatchedAudienceToken.split("\\.");
        String unsignedToken = parts[0] + "." + parts[1];
        OAuth2AccessToken refreshedAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                mismatchedAudienceToken, Instant.now(), Instant.now().plusSeconds(300));
        when(authorizedClientProvider.authorize(any()))
                .thenReturn(new OAuth2AuthorizedClient(clientRegistration, "alice", refreshedAccessToken));

        MockHttpServletRequest request = requestHolding(Instant.now().minusSeconds(60));
        request
                .getSession()
                .setAttribute(OAuth2Constants.REFRESH_TOKEN_SESSION_ATTRIBUTE,
                        new OAuth2RefreshToken("refresh-token-value", Instant.now().minusSeconds(3600)));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);

        // when
        filter.doFilter(request, response, mock(FilterChain.class));

        // then
        verify(auditLogService)
                .logAuthentication(eq(Operation.AUTHENTICATION), eq(OperationResult.FAILURE), message.capture(),
                        eq(unsignedToken));
        assertThat(message.getValue()).contains(unsignedToken).doesNotContain(parts[2]);
    }

    private void configureProvider() {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        settings.getOAuth2Providers().put(REGISTRATION_ID, new OAuth2ProviderSettingsDto());
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, settings);
        when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(clientRegistration());
    }

    private MockHttpServletResponse refreshRefusedWith(OAuth2Error error) throws Exception {
        configureProvider();
        when(authorizedClientProvider.authorize(any()))
                .thenThrow(new ClientAuthorizationException(error, REGISTRATION_ID));
        MockHttpServletRequest request = requestHolding(Instant.now().minusSeconds(60));
        request
                .getSession()
                .setAttribute(OAuth2Constants.REFRESH_TOKEN_SESSION_ATTRIBUTE,
                        new OAuth2RefreshToken("refresh-token-value", Instant.now().minusSeconds(3600)));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, mock(FilterChain.class));
        return response;
    }

    private MockHttpServletRequest requestHolding(Instant accessTokenExpiry) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/auth/profile");
        request
                .getSession()
                .setAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE,
                        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken,
                                accessTokenExpiry.minusSeconds(3600), accessTokenExpiry));
        return request;
    }

    private static ClientRegistration clientRegistration() {
        return ClientRegistration
                .withRegistrationId(REGISTRATION_ID)
                .clientId("core")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://core.example/login/oauth2/code/" + REGISTRATION_ID)
                .authorizationUri("https://idp.example/authorize")
                .tokenUri("https://idp.example/token")
                .scope("openid")
                .build();
    }
}
