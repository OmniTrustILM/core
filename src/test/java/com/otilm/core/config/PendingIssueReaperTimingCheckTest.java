package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyProperties;
import java.time.Duration;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.util.unit.DataSize;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PendingIssueReaperTimingCheckTest {

    private static final Duration DEFAULT_REAP_STALE_AFTER = Duration.ofMinutes(30);

    @Test
    void accepts_whenTheDefaultsAreConfigured() {
        // given
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(DEFAULT_REAP_STALE_AFTER,
                createClient(Duration.ofSeconds(35)), provideProxy(null));

        // when
        ThrowingCallable checkTimings = check::check;

        // then
        assertThatCode(checkTimings).doesNotThrowAnyException();
    }

    /**
     * The reaper fails a certificate whose claim is older than reap-stale-after, which must only ever mean the
     * synchronous connector call is gone, so one call has to end within it.
     */
    @Test
    void refuses_whenAConnectorCallCouldOutlastTheReapDelay() {
        // given
        Duration slowResponse = Duration.ofSeconds(115);
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(Duration.ofMinutes(1),
                createClient(slowResponse), provideProxy(null));

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
        ProxyProperties proxy = mock(ProxyProperties.class);
        when(proxy.requestTimeout()).thenReturn(Duration.ofMinutes(5));
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(Duration.ofMinutes(5),
                createClient(Duration.ofSeconds(35)), provideProxy(proxy));

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

    @SuppressWarnings("unchecked")
    private static ObjectProvider<ProxyProperties> provideProxy(ProxyProperties proxy) {
        ObjectProvider<ProxyProperties> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(proxy);
        return provider;
    }
}
