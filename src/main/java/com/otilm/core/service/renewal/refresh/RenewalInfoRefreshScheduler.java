package com.otilm.core.service.renewal.refresh;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Triggers the refresh of renewal information on every node; the claim lets one node at a time take the due work. */
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class RenewalInfoRefreshScheduler {

    private final RenewalInfoRefreshRunner runner;

    public RenewalInfoRefreshScheduler(RenewalInfoRefreshRunner runner) {
        this.runner = runner;
    }

    @Scheduled(fixedDelayString = "${provider.renewal-info.sweep-interval-ms:60000}")
    public void sweepScheduled() {
        runner.sweep();
    }
}
