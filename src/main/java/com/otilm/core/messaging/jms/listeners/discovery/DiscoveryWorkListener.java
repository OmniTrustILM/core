package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryProcessTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import com.otilm.core.service.writer.discovery.DiscoveryWorkLease;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Consumes {@code provider.discovery-work} ticks and hands each admitted one to the worker for its type.
 *
 * <p>
 * Transaction-free: a tick calls the connector, and a connector call must never run inside a transaction or hold a row
 * lock. Each worker opens its own short transactions around the writes its answer justifies.
 *
 * <p>
 * <b>Admission.</b> A tick runs only while its agenda row is still leased to the token its message carries. A duplicate
 * delivery, or a message a newer claim outlived, ends here without calling the worker.
 *
 * <p>
 * <b>A tick that does not say what happens next is retried at its next rung.</b> That covers a worker that failed,
 * whether it caught the failure and charged the budget or let it escape: the row moves one attempt up its ladder and
 * the lease is freed. An escaping failure is logged and acknowledged rather than handed to the broker, whose redelivery
 * would add a second, uncoordinated retry loop on top of the agenda's.
 */
@Component
public class DiscoveryWorkListener implements MessageProcessor<DiscoveryWorkMessage> {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryWorkListener.class);

    private final DiscoveryWorkLease lease;
    private final DiscoveryWorkProperties workProperties;
    private final DiscoveryStatusTickWorker statusWorker;
    private final DiscoveryDrainTickWorker drainWorker;
    private final DiscoveryProcessTickWorker processWorker;

    public DiscoveryWorkListener(DiscoveryWorkLease lease, DiscoveryWorkProperties workProperties,
            DiscoveryStatusTickWorker statusWorker, DiscoveryDrainTickWorker drainWorker,
            DiscoveryProcessTickWorker processWorker) {
        this.lease = lease;
        this.workProperties = workProperties;
        this.statusWorker = statusWorker;
        this.drainWorker = drainWorker;
        this.processWorker = processWorker;
    }

    @Override
    public void processMessage(DiscoveryWorkMessage message) {
        Optional<DiscoveryWorkTick> admitted;
        try {
            admitted = lease.admit(message);
        } catch (RuntimeException e) {
            logger
                    .error("Could not admit discovery {} tick for run {}; the sweep claims its row again once the "
                            + "lease runs out", message.workType(), message.discoveryUuid(), e);
            return;
        }
        if (admitted.isEmpty()) {
            logger
                    .debug("Dropping discovery {} tick for run {}: its row is no longer leased to it",
                            message.workType(), message.discoveryUuid());
            return;
        }
        DiscoveryWorkTick tick = admitted.get();
        try {
            switch (tick.workType()) {
                case STATUS -> statusWorker.tick(tick);
                case DRAIN -> drainWorker.tick(tick);
                case PROCESS -> processWorker.tick(tick);
            }
        } catch (RuntimeException e) {
            logger
                    .error("Discovery {} tick failed for run {} (attempt {}); the agenda row retries when next due",
                            tick.workType(), tick.discoveryUuid(), tick.attempt(), e);
        } finally {
            retryUnresolved(tick);
        }
    }

    private void retryUnresolved(DiscoveryWorkTick tick) {
        if (tick.resolved()) {
            return;
        }
        int nextAttempt = tick.attempt() + 1;
        OffsetDateTime nextDueAt = OffsetDateTime
                .now(ZoneOffset.UTC)
                .plus(workProperties.scheduleFor(tick.workType()).delayFor(nextAttempt));
        try {
            tick.reschedule(nextAttempt, nextDueAt);
        } catch (RuntimeException e) {
            logger
                    .warn("Could not reschedule discovery {} tick for run {}; the sweep claims its row again once "
                            + "the lease runs out", tick.workType(), tick.discoveryUuid(), e);
        }
    }
}
