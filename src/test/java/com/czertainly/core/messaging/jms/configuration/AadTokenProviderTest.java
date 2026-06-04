package com.czertainly.core.messaging.jms.configuration;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AadTokenProviderTest {

    private static final int REFRESH_BUFFER_SECONDS = 60;
    private static final int GETTING_TIMEOUT_SECONDS = 5;

    @Mock
    private TokenCredential credential;

    private AadTokenProvider provider;

    @BeforeEach
    void setUp() {
        provider = new AadTokenProvider(credential, REFRESH_BUFFER_SECONDS, GETTING_TIMEOUT_SECONDS);
    }

    @Test
    void getToken_firstCall_invokesCredentialAndCachesResult() {
        AccessToken token = new AccessToken("token-1", OffsetDateTime.now().plusHours(1));
        when(credential.getToken(any(TokenRequestContext.class))).thenReturn(Mono.just(token));

        String result = provider.getToken();

        assertThat(result).isEqualTo("token-1");
        verify(credential, times(1)).getToken(any(TokenRequestContext.class));
    }

    @Test
    void getToken_secondCallWithinValidity_reusesCachedTokenWithoutInvokingCredentialAgain() {
        AccessToken token = new AccessToken("token-1", OffsetDateTime.now().plusHours(1));
        when(credential.getToken(any(TokenRequestContext.class))).thenReturn(Mono.just(token));

        provider.getToken();
        String second = provider.getToken();

        assertThat(second).isEqualTo("token-1");
        verify(credential, times(1)).getToken(any(TokenRequestContext.class));
    }

    @Test
    void getToken_whenExpiryIsInsideRefreshBuffer_triggersRefresh() {
        // expiry is "now + (buffer - 1)" — production code's `now + buffer` will land past expiry,
        // forcing shouldRefreshToken() to return true on the second call.
        AccessToken nearExpiry = new AccessToken(
                "old-token",
                OffsetDateTime.now().plusSeconds(REFRESH_BUFFER_SECONDS - 1)
        );
        AccessToken fresh = new AccessToken(
                "new-token",
                OffsetDateTime.now().plusHours(1)
        );
        when(credential.getToken(any(TokenRequestContext.class)))
                .thenReturn(Mono.just(nearExpiry))
                .thenReturn(Mono.just(fresh));

        String first = provider.getToken();
        String second = provider.getToken();

        assertThat(first).isEqualTo("old-token");
        assertThat(second).isEqualTo("new-token");
        verify(credential, times(2)).getToken(any(TokenRequestContext.class));
    }

    @Test
    void apply_returnsSameTokenAsGetToken() {
        AccessToken token = new AccessToken("apply-token", OffsetDateTime.now().plusHours(1));
        when(credential.getToken(any(TokenRequestContext.class))).thenReturn(Mono.just(token));

        Object applied = provider.apply(null, null);

        assertThat(applied).isEqualTo("apply-token");
    }

    @Test
    void getToken_whenCredentialReturnsEmptyMono_throwsRuntimeException() {
        when(credential.getToken(any(TokenRequestContext.class))).thenReturn(Mono.empty());

        assertThatThrownBy(() -> provider.getToken())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to acquire AAD token");
    }

    @Test
    void getToken_whenCredentialErrors_wrapsInRuntimeExceptionPreservingCause() {
        IllegalStateException underlying = new IllegalStateException("network down");
        when(credential.getToken(any(TokenRequestContext.class))).thenReturn(Mono.error(underlying));

        assertThatThrownBy(() -> provider.getToken())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to acquire AAD token")
                .hasRootCauseMessage("network down");
    }
}
