package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.auth.oauth2.AuthenticationSnapshotRequestHolder;
import com.otilm.core.auth.oauth2.PlatformJwtDecoder;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.AuthHelper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class BearerTokenDelegationTest {

    private final PlatformJwtDecoder decoder = mock(PlatformJwtDecoder.class);
    private final PlatformAuthenticationClient client = mock(PlatformAuthenticationClient.class);
    private final BearerTokenAuthenticator authenticator = new BearerTokenAuthenticator(decoder, client,
            new TspSecurityContextWriter(mock(AuthHelper.class)));
    private AuthenticationSettingsDto previous;
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    @BeforeEach
    void setUp() {
        previous = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        var provider = new OAuth2ProviderSettingsDto();
        provider.setIssuerUrl("https://issuer.example");
        provider.setName("provider");
        provider.setAllowedDelegates(List.of("mcp"));
        var settings = new AuthenticationSettingsDto();
        settings.setOAuth2Providers(Map.of("provider", provider));
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, settings);
        request.addHeader("Authorization", "Bearer token");
    }

    @AfterEach
    void clear() {
        new SettingsCache().cacheSettings(SettingsSection.AUTHENTICATION, previous);
        AuthenticationSnapshotRequestHolder.clear();
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @Test
    void timestampingRecordsTheDelegateAndAuthorizesTheSameUser() {
        when(decoder.decode("token")).thenReturn(jwt(Map.of("client_id", "mcp", "sub", "service-account")));
        when(client.authenticateByToken(any(), anyLong())).thenReturn(identity());
        assertThat(authenticator.authenticate(request, null)).isTrue();
        assertThat(LoggingHelper.getActorInfo().delegate()).isEqualTo(new DelegateRecord("mcp", "service-account"));
        assertThat(((PlatformUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal())
                .getUsername()).isEqualTo("alice");
    }

    @Test
    void timestampingRejectsUnallowedDelegateBeforeLookingUpTheUser() {
        when(decoder.decode("token")).thenReturn(jwt(Map.of("client_id", "unallowed")));
        assertThat(authenticator.authenticate(request, null)).isFalse();
        verifyNoInteractions(client);
        assertThat(LoggingHelper.getActorInfo().delegate()).isNull();
    }

    @Test
    void ordinaryTimestampingAuthenticationClearsThePreviousDelegate() {
        LoggingHelper.putDelegateInfo(new DelegateRecord("previous", null));
        when(decoder.decode("token")).thenReturn(jwt(null));
        when(client.authenticateByToken(any(), anyLong())).thenReturn(identity());
        assertThat(authenticator.authenticate(request, null)).isTrue();
        assertThat(LoggingHelper.getActorInfo().delegate()).isNull();
    }

    private Jwt jwt(Object actor) {
        var token = Jwt
                .withTokenValue("token")
                .header("alg", "RS256")
                .issuer("https://issuer.example")
                .claim("username", "alice");
        if (actor != null) {
            token.claim("act", actor);
        }
        return token.build();
    }

    private AuthenticationInfo identity() {
        return new AuthenticationInfo(AuthMethod.TOKEN, "e9838918-5e7c-4594-aa54-ec4088db6382", "alice", List.of());
    }
}
