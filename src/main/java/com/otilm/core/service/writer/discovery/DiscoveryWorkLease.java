package com.otilm.core.service.writer.discovery;

import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The lease a discovery tick holds on its {@code discovery_work} row, from admission to release. Every write is
 * conditional on the tick's token, so a tick whose row was reclaimed, rescheduled by a lifecycle change or deleted
 * changes nothing. The writes themselves are {@link DiscoveryWorkWriter}'s, each in its own transaction or the
 * caller's.
 *
 * <p>
 * Workers reach these writes through {@link DiscoveryWorkTick}, never directly.
 */
@Component
public class DiscoveryWorkLease {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryWorkLease.class);

    private final DiscoveryWorkWriter workWriter;
    private final Duration leaseDuration;

    public DiscoveryWorkLease(DiscoveryWorkWriter workWriter,
            @Value("${discovery.work.lease-duration:PT2M}") Duration leaseDuration) {
        // A lease that is over when it is taken leaves every claimed row claimable again at once, so each sweep would
        // publish a second tick for work already running.
        if (leaseDuration.isZero() || leaseDuration.isNegative()) {
            throw new IllegalArgumentException("discovery.work.lease-duration must be positive");
        }
        this.workWriter = workWriter;
        this.leaseDuration = leaseDuration;
    }

    /**
     * Lets a tick message run only while its row is still leased to it, and renews that lease for the tick's work. A
     * message without a token was published by a Core version without the lease; it runs only on a row no tick holds,
     * and takes the row under a new token.
     *
     * @return the tick to run, or empty when the message is a duplicate, outlived by a newer claim, or for a row that
     * is gone
     */
    public Optional<DiscoveryWorkTick> admit(DiscoveryWorkMessage message) {
        OffsetDateTime now = now();
        OffsetDateTime leasedUntil = now.plus(leaseDuration);
        UUID token = message.leaseToken();
        boolean leased;
        if (token != null) {
            leased = workWriter.renewLease(message.discoveryUuid(), message.workType(), token, leasedUntil);
        } else {
            token = UUID.randomUUID();
            leased = workWriter.leaseIfFree(message.discoveryUuid(), message.workType(), token, leasedUntil, now);
        }
        if (!leased) {
            return Optional.empty();
        }
        return Optional
                .of(new DiscoveryWorkTick(this, message.discoveryUuid(), message.workType(), message.attempt(), token));
    }

    /**
     * Schedules the run's {@code workType} row already leased to a new tick, for a caller that publishes that tick
     * itself instead of leaving it to the sweep. Joins the caller's transaction.
     *
     * @return the tick's message, to publish once that transaction has committed
     */
    public DiscoveryWorkMessage scheduleLeased(UUID discoveryUuid, DiscoveryWorkType workType) {
        UUID token = UUID.randomUUID();
        workWriter.scheduleLeased(discoveryUuid, workType, token, now().plus(leaseDuration));
        return new DiscoveryWorkMessage(discoveryUuid, workType, 0, token);
    }

    void renew(DiscoveryWorkTick tick) {
        if (!workWriter.renewLease(tick.discoveryUuid(), tick.workType(), tick.token(), now().plus(leaseDuration))) {
            logger
                    .debug("Discovery {} tick for run {} no longer holds its row; its writes will change nothing",
                            tick.workType(), tick.discoveryUuid());
        }
    }

    void reschedule(DiscoveryWorkTick tick, int attempt, OffsetDateTime nextDueAt) {
        workWriter.rescheduleLeased(tick.discoveryUuid(), tick.workType(), tick.token(), attempt, nextDueAt);
    }

    void release(DiscoveryWorkTick tick) {
        workWriter.releaseLease(tick.discoveryUuid(), tick.workType(), tick.token());
    }

    Optional<DiscoveryWorkMessage> handOver(DiscoveryWorkTick tick) {
        UUID nextToken = UUID.randomUUID();
        if (!workWriter
                .handOverLease(tick.discoveryUuid(), tick.workType(), tick.token(), nextToken,
                        now().plus(leaseDuration))) {
            return Optional.empty();
        }
        return Optional.of(new DiscoveryWorkMessage(tick.discoveryUuid(), tick.workType(), 0, nextToken));
    }

    private static OffsetDateTime now() {
        return OffsetDateTime.now(ZoneOffset.UTC);
    }
}
