package com.otilm.core.service.writer.discovery;

import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The lease a discovery tick holds on its {@code discovery_work} row, from admission to release. A tick writes to its
 * row through {@link DiscoveryWorkTick}.
 */
@Component
public class DiscoveryWorkLease {

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
     * Admits a tick message only while its row is still leased to the message's token, and moves the lease to a fresh
     * token the tick alone holds, so a second copy of the message finds its token gone. A message without a token comes
     * from a Core version without the lease and is admitted only on a row no tick holds.
     *
     * @return the tick to run, or empty when another copy of the message was already admitted, a newer claim outlived
     * it, or its row is gone
     */
    public Optional<DiscoveryWorkTick> admit(DiscoveryWorkMessage message) {
        OffsetDateTime now = now();
        OffsetDateTime leasedUntil = now.plus(leaseDuration);
        UUID tickToken = UUID.randomUUID();
        boolean leased = message.leaseToken() != null
                ? workWriter
                        .swapLease(message.discoveryUuid(), message.workType(), message.leaseToken(), tickToken,
                                leasedUntil)
                : workWriter.leaseIfFree(message.discoveryUuid(), message.workType(), tickToken, leasedUntil, now);
        if (!leased) {
            return Optional.empty();
        }
        return Optional
                .of(new DiscoveryWorkTick(this, message.discoveryUuid(), message.workType(), message.attempt(),
                        tickToken));
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

    boolean renew(DiscoveryWorkTick tick) {
        return workWriter.renewLease(tick.discoveryUuid(), tick.workType(), tick.token(), now().plus(leaseDuration));
    }

    void reschedule(DiscoveryWorkTick tick, int attempt, OffsetDateTime nextDueAt) {
        workWriter.rescheduleLeased(tick.discoveryUuid(), tick.workType(), tick.token(), attempt, nextDueAt);
    }

    void deferBusy(DiscoveryWorkTick tick, OffsetDateTime nextDueAt) {
        workWriter
                .deferBusyLeased(tick.discoveryUuid(), tick.workType(), tick.token(), tick.attempt(), nextDueAt, now());
    }

    void release(DiscoveryWorkTick tick) {
        workWriter.releaseLease(tick.discoveryUuid(), tick.workType(), tick.token(), now());
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
