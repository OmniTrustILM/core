package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyProperties;
import java.time.Duration;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.util.unit.DataSize;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PendingIssueReaperTimingCheckTest {

    private static final Duration DEFAULT_REAP_STALE_AFTER = Duration.ofMinutes(30);

    @Mock
    private ProxyProperties proxy;
    @Mock
    private ObjectProvider<ProxyProperties> proxyProvider;

    @Test
    void accepts_whenTheDefaultsAreConfigured() {
        // given
        when(proxyProvider.getIfAvailable()).thenReturn(null);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(DEFAULT_REAP_STALE_AFTER,
                createClient(Duration.ofSeconds(35)), proxyProvider);

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatCode(checkTimings).doesNotThrowAnyException();
    }

    @Test
    void refuses_whenSecretReadsAndTheRequestCouldOutlastTheReapDelay() {
        // given — at the default timeouts one connector call can take 48 s; two secret reads of four vault calls each
        // and the request make nine, which this delay covers only three of
        Duration reapDelayShortOfNineCalls = Duration.ofMinutes(5);
        when(proxyProvider.getIfAvailable()).thenReturn(null);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(reapDelayShortOfNineCalls,
                createClient(Duration.ofSeconds(35)), proxyProvider);

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatThrownBy(checkTimings)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("reap-stale-after must be longer than PT7M12S")
                .hasMessageContaining("was " + reapDelayShortOfNineCalls);
    }

    @Test
    void refuses_whenAConnectorCallCouldOutlastTheReapDelay() {
        // given
        Duration slowResponse = Duration.ofSeconds(115);
        Duration reapDelayForOneSlowCall = Duration.ofMinutes(1);
        when(proxyProvider.getIfAvailable()).thenReturn(null);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(reapDelayForOneSlowCall,
                createClient(slowResponse), proxyProvider);

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatThrownBy(checkTimings)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("reap-stale-after must be longer than PT19M12S")
                .hasMessageContaining("was " + reapDelayForOneSlowCall);
    }

    @Test
    void refuses_whenAProxyRequestCouldOutlastTheReapDelay() {
        // given
        Duration proxyRequestTimeout = Duration.ofMinutes(5);
        Duration reapDelayForOneProxyRequest = Duration.ofMinutes(5);
        when(proxy.requestTimeout()).thenReturn(proxyRequestTimeout);
        when(proxyProvider.getIfAvailable()).thenReturn(proxy);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(reapDelayForOneProxyRequest,
                createClient(Duration.ofSeconds(35)), proxyProvider);

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatThrownBy(checkTimings)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("reap-stale-after must be longer than PT45M45S")
                .hasMessageContaining("was " + reapDelayForOneProxyRequest);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ConnectorApiClientProperties createClient(Duration responseTimeout) {
        return new ConnectorApiClientProperties(Duration.ofSeconds(3), responseTimeout, 20, Duration.ofSeconds(10),
                DataSize.ofMegabytes(16));
    }
}
