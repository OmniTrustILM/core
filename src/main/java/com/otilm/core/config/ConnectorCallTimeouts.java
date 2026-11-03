package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyClientImpl;
import com.otilm.core.messaging.proxy.ProxyProperties;
import java.time.Duration;
import org.jspecify.annotations.Nullable;

/** The longest one connector call can take at the timeouts configured, made directly or through the proxy. */
final class ConnectorCallTimeouts {

    private ConnectorCallTimeouts() {
    }

    static Duration longestCall(ConnectorApiClientProperties connectorClient, @Nullable ProxyProperties proxy) {
        Duration call = connectorClient
                .pendingAcquireTimeout()
                .plus(connectorClient.connectTimeout())
                .plus(connectorClient.responseTimeout());
        if (proxy != null) {
            Duration proxiedCall = proxy.requestTimeout().plusMillis(ProxyClientImpl.MESSAGE_ROUND_TRIP_BUFFER_MS);
            call = proxiedCall.compareTo(call) > 0 ? proxiedCall : call;
        }
        return call;
    }
}
