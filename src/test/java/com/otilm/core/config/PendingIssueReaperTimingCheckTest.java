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

    /**
     * The reaper fails a certificate whose claim is older than reap-stale-after, which must only ever mean the
     * synchronous connector call is gone, so the call has to end within it.
     */
    @Test
    void refuses_whenAConnectorCallCouldOutlastTheReapDelay() {
        // given
        Duration slowResponse = Duration.ofSeconds(115);
        when(proxyProvider.getIfAvailable()).thenReturn(null);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(Duration.ofMinutes(1),
                createClient(slowResponse), proxyProvider);

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatThrownBy(checkTimings)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("reap-stale-after must be longer than PT2M8S")
                .hasMessageContaining("was PT1M");
    }

    @Test
    void refuses_whenAProxyRequestCouldOutlastTheReapDelay() {
        // given
        when(proxy.requestTimeout()).thenReturn(Duration.ofMinutes(5));
        when(proxyProvider.getIfAvailable()).thenReturn(proxy);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(Duration.ofMinutes(5),
                createClient(Duration.ofSeconds(35)), proxyProvider);

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatThrownBy(checkTimings)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("reap-stale-after must be longer than PT5M5S")
                .hasMessageContaining("was PT5M");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ConnectorApiClientProperties createClient(Duration responseTimeout) {
        return new ConnectorApiClientProperties(Duration.ofSeconds(3), responseTimeout, 20, Duration.ofSeconds(10),
                DataSize.ofMegabytes(16));
    }
}
