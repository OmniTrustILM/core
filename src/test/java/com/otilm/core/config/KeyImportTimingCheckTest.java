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

class KeyImportTimingCheckTest {

    private static final KeyImportProperties DEFAULTS = new KeyImportProperties(null, null, null, null, null, null);

    @Test
    void theDefaultsFit() {
        // given
        KeyImportTimingCheck check = new KeyImportTimingCheck(DEFAULTS, client(Duration.ofSeconds(35)), noProxy());

        // when
        // then
        assertThatCode(check::check).doesNotThrowAnyException();
    }

    /**
     * The requester owns an import for the retry window, so its request with the connector calls around its wait, and
     * one look at the import, both of up to three connector calls, must end within it.
     */
    @Test
    void aRetryWindowARequestCouldOutlastIsRefused() {
        // given
        ConnectorApiClientProperties slow = client(Duration.ofSeconds(115));
        KeyImportProperties keyImport = new KeyImportProperties(null, null, null, Duration.ofMinutes(5), null, null);
        KeyImportTimingCheck check = new KeyImportTimingCheck(keyImport, slow, noProxy());

        // when
        // then
        assertThatThrownBy(check::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("key-import.retry-window must be at least PT7M24S, the request timeout and three "
                        + "connector calls at the connector timeouts configured, was PT5M");
    }

    @Test
    void aProxyRequestIsAConnectorCall() {
        // given
        ProxyProperties proxy = mock(ProxyProperties.class);
        when(proxy.requestTimeout()).thenReturn(Duration.ofMinutes(5));
        ObjectProvider<ProxyProperties> proxied = provider(proxy);
        KeyImportTimingCheck check = new KeyImportTimingCheck(DEFAULTS, client(Duration.ofSeconds(35)), proxied);

        // when
        // then
        assertThatThrownBy(check::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("key-import.retry-window must be at least PT16M15S, the request timeout and three "
                        + "connector calls at the connector timeouts configured, was PT15M");
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
