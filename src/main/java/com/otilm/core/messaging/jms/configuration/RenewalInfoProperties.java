package com.otilm.core.messaging.jms.configuration;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Pacing of the refresh of authority renewal information. A value left unset takes its default.
 *
 * @param sweepIntervalMs how often a node looks for certificates due for a refresh
 * @param maxPerAuthority certificates of one authority claimed per sweep
 * @param enrolPerSweep certificates without refresh state enrolled per sweep
 * @param backoff delays after failed refreshes; the last one repeats
 * @param lease how long a claimed certificate stays claimed before another node may claim it again
 * @param executorThreads threads calling connectors
 */
@ConfigurationProperties("provider.renewal-info")
public record RenewalInfoProperties(long sweepIntervalMs, int maxPerAuthority, int enrolPerSweep,
        List<Duration> backoff, Duration lease, int executorThreads) {

    public static final List<Duration> DEFAULT_BACKOFF = List
            .of(Duration.ofMinutes(5), Duration.ofMinutes(15), Duration.ofHours(1), Duration.ofHours(6));

    public RenewalInfoProperties {
        sweepIntervalMs = sweepIntervalMs > 0 ? sweepIntervalMs : 60_000;
        maxPerAuthority = maxPerAuthority > 0 ? maxPerAuthority : 200;
        enrolPerSweep = enrolPerSweep > 0 ? enrolPerSweep : 500;
        backoff = backoff == null || backoff.isEmpty() ? DEFAULT_BACKOFF : List.copyOf(backoff);
        lease = lease == null ? Duration.ofMinutes(15) : lease;
        executorThreads = executorThreads > 0 ? executorThreads : 4;
    }
}
