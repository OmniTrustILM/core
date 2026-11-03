package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyProperties;
import jakarta.annotation.PostConstruct;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Refuses at startup a pending-issue reap delay that one connector call could outlast at the connector timeouts
 * configured: the reaper fails a certificate whose claim is that old, which must only ever mean the synchronous call to
 * the authority is gone, never that it is still running.
 */
@Component
public class PendingIssueReaperTimingCheck {

    private final Duration reapStaleAfter;
    private final ConnectorApiClientProperties connectorClient;
    private final ObjectProvider<ProxyProperties> proxy;

    public PendingIssueReaperTimingCheck(
            @Value("${provider.status-poll.reap-stale-after:PT30M}") Duration reapStaleAfter,
            ConnectorApiClientProperties connectorClient, ObjectProvider<ProxyProperties> proxy) {
        this.reapStaleAfter = reapStaleAfter;
        this.connectorClient = connectorClient;
        this.proxy = proxy;
    }

    @PostConstruct
    void check() {
        Duration call = ConnectorCallTimeouts.longestCall(connectorClient, proxy.getIfAvailable());
        if (reapStaleAfter.compareTo(call) <= 0) {
            throw new IllegalStateException("provider.status-poll.reap-stale-after must be longer than " + call
                    + ", the longest connector call at the connector timeouts configured, was " + reapStaleAfter);
        }
    }
}
