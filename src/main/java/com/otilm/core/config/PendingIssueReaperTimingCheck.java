package com.otilm.core.config;

import com.otilm.core.messaging.proxy.ProxyProperties;
import jakarta.annotation.PostConstruct;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Refuses at startup a pending-issue reap delay that a typical synchronous phase of a claimed certificate could outlast
 * at the connector timeouts configured: the reaper fails a certificate whose claim is that old, which must only ever
 * mean the synchronous call to the authority is gone, never that it is still running. This is a minimum, not a bound:
 * each further secret reference adds four calls, so a delay just above it can still fail a live issuance.
 */
@Component
public class PendingIssueReaperTimingCheck {

    /**
     * The connector calls of a typical claimed phase: one vault-backed secret referenced by the authority attributes
     * and one by the RA profile attributes, each read in four calls to the vault connector (its vault and vault profile
     * attributes, the secret's attributes, then its content), then the request to the authority. Each further secret
     * reference adds four calls this count leaves out.
     */
    private static final int CONNECTOR_CALLS = 9;

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
        Duration needed = ConnectorCallTimeouts
                .longestCall(connectorClient, proxy.getIfAvailable())
                .multipliedBy(CONNECTOR_CALLS);
        if (reapStaleAfter.compareTo(needed) <= 0) {
            throw new IllegalStateException("provider.status-poll.reap-stale-after must be longer than " + needed
                    + ", nine connector calls at the connector timeouts configured, was " + reapStaleAfter);
        }
    }
}
