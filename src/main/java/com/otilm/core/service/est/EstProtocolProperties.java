package com.otilm.core.service.est;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;

/**
 * How often a waiting EST request reads the state it waits for, bound from {@code est.protocol.*}. How long it waits
 * and what {@code Retry-After} it sends are settings of its EST Profile. A value left out takes its default, one
 * without a unit is in seconds, as CMP's poll timeout is, and one out of range fails at startup.
 *
 * @param issueWait how a request that EST has just submitted or completed reads the state of its certificate
 */
@ConfigurationProperties(prefix = "est.protocol")
public record EstProtocolProperties(IssueWait issueWait) {

    public EstProtocolProperties {
        issueWait = issueWait == null ? new IssueWait(null) : issueWait;
    }

    /**
     * @param interval how long the request waits between two reads of the state of the certificate; at least 100
     * milliseconds, so that a waiting request reads the database at most ten times a second
     */
    public record IssueWait(@DurationUnit(ChronoUnit.SECONDS) Duration interval) {

        private static final Duration SHORTEST_INTERVAL = Duration.ofMillis(100);

        public IssueWait {
            interval = interval == null ? Duration.ofSeconds(1) : interval;
            if (interval.compareTo(SHORTEST_INTERVAL) < 0) {
                throw new IllegalArgumentException(
                        "est.protocol.issue-wait.interval must be at least 100 milliseconds, was " + interval);
            }
        }
    }
}
