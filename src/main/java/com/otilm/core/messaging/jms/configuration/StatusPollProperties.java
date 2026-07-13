package com.otilm.core.messaging.jms.configuration;

import com.otilm.core.service.handler.authority.CertificateOperation;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@ConfigurationProperties("provider.status-poll")
public record StatusPollProperties(
        PollSchedule defaults,
        Map<CertificateOperation, PollSchedule> byKind
) {
    public record PollSchedule(List<Duration> delays, int maxAttempts) {
        public Duration delayFor(int attempt) {
            if (attempt <= 0) return delays.get(0);
            int idx = Math.min(attempt - 1, delays.size() - 1);
            return delays.get(idx);
        }

        /**
         * The attempt value at which the backoff ramp has reached its final (ceiling) delay.
         * Resetting a row's attempt down refreshes the poll-timeout budget ({@code maxAttempts − ceilingAttempt()}
         * further polls) without restarting the ramp — the cadence stays at the ceiling.
         */
        public int ceilingAttempt() {
            return delays.size();
        }
    }

    public PollSchedule scheduleFor(CertificateOperation op) {
        if (byKind != null && byKind.containsKey(op)) {
            return byKind.get(op);
        }
        return defaults;
    }
}
