package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyProperties;
import java.time.Duration;
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
    void theDefaultsFit() {
        // given
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(DEFAULT_REAP_STALE_AFTER,
                client(Duration.ofSeconds(35)), noProxy());

        // when
        // then
        assertThatCode(check::check).doesNotThrowAnyException();
    }

    /**
     * The reaper fails a certificate whose claim is older than reap-stale-after, which must only ever mean the
     * synchronous connector call is gone, so one call has to end within it.
     */
    @Test
    void aReapDelayAConnectorCallCouldOutlastIsRefused() {
        // given
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(Duration.ofMinutes(1),
                client(Duration.ofSeconds(115)), noProxy());

        // when
        // then
        assertThatThrownBy(check::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("provider.status-poll.reap-stale-after must be longer than PT2M8S, the longest connector "
                        + "call at the connector timeouts configured, was PT1M");
    }

    @Test
    void aProxyRequestIsAConnectorCall() {
        // given
        ProxyProperties proxy = mock(ProxyProperties.class);
        when(proxy.requestTimeout()).thenReturn(Duration.ofMinutes(5));
        PendingIssueReaperTimingCheck check = new PendingIssueReaperTimingCheck(Duration.ofMinutes(5),
                client(Duration.ofSeconds(35)), provider(proxy));

        // when
        // then
        assertThatThrownBy(check::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("provider.status-poll.reap-stale-after must be longer than PT5M5S, the longest connector "
                        + "call at the connector timeouts configured, was PT5M");
    }

    private static ConnectorApiClientProperties client(Duration responseTimeout) {
        return new ConnectorApiClientProperties(Duration.ofSeconds(3), responseTimeout, 20, Duration.ofSeconds(10),
                DataSize.ofMegabytes(16));
    }

    private static ObjectProvider<ProxyProperties> noProxy() {
        return provider(null);
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<ProxyProperties> provider(ProxyProperties proxy) {
        ObjectProvider<ProxyProperties> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(proxy);
        return provider;
    }
}
