package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyClientImpl;
import com.otilm.core.messaging.proxy.ProxyProperties;
import jakarta.annotation.PostConstruct;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Refuses at startup a key import retry window that a request or a look of the reconciliation could outlast at the
 * connector timeouts configured: the requester owns an import for the window, and the reconciliation takes it over once
 * the window has passed.
 */
@Component
public class KeyImportTimingCheck {

    /** The connector calls around a request's wait, an import, a last poll and a cancel, or in a look at an import. */
    private static final int CONNECTOR_CALLS = 3;

    private final KeyImportProperties keyImport;
    private final ConnectorApiClientProperties connectorClient;
    private final ObjectProvider<ProxyProperties> proxy;

    public KeyImportTimingCheck(KeyImportProperties keyImport, ConnectorApiClientProperties connectorClient,
            ObjectProvider<ProxyProperties> proxy) {
        this.keyImport = keyImport;
        this.connectorClient = connectorClient;
        this.proxy = proxy;
    }

    @PostConstruct
    void check() {
        Duration call = connectorClient
                .pendingAcquireTimeout()
                .plus(connectorClient.connectTimeout())
                .plus(connectorClient.responseTimeout());
        ProxyProperties proxied = proxy.getIfAvailable();
        if (proxied != null) {
            Duration proxiedCall = proxied.requestTimeout().plusMillis(ProxyClientImpl.MESSAGE_ROUND_TRIP_BUFFER_MS);
            call = proxiedCall.compareTo(call) > 0 ? proxiedCall : call;
        }
        Duration needed = keyImport.requestTimeout().plus(call.multipliedBy(CONNECTOR_CALLS));
        if (keyImport.retryWindow().compareTo(needed) < 0) {
            throw new IllegalStateException("key-import.retry-window must be at least " + needed
                    + ", the request timeout and three connector calls at the connector timeouts configured, was "
                    + keyImport.retryWindow());
        }
    }
}
