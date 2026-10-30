package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryProcessTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Consumes {@code provider.discovery-work} ticks and hands each to the worker for its type.
 *
 * <p>
 * Transaction-free: a tick calls the connector, and a connector call must never run inside a transaction or hold a row
 * lock. Each worker opens its own short transactions around the writes its answer justifies.
 *
 * <p>
 * <b>A failed tick is logged and acknowledged; its agenda row retries it when next due.</b> Retry is the
 * {@code discovery_work} agenda's job: the row was already pushed up its backoff ladder when the tick was claimed, so
 * the sweep re-publishes it when it next comes due. Letting the exception reach the broker would add a second,
 * uncoordinated retry loop on top of that one, at the broker's cadence rather than the run's.
 */
@Component
public class DiscoveryWorkListener implements MessageProcessor<DiscoveryWorkMessage> {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryWorkListener.class);

    private final DiscoveryStatusTickWorker statusWorker;
    private final DiscoveryDrainTickWorker drainWorker;
    private final DiscoveryProcessTickWorker processWorker;

    public DiscoveryWorkListener(DiscoveryStatusTickWorker statusWorker, DiscoveryDrainTickWorker drainWorker,
            DiscoveryProcessTickWorker processWorker) {
        this.statusWorker = statusWorker;
        this.drainWorker = drainWorker;
        this.processWorker = processWorker;
    }

    @Override
    public void processMessage(DiscoveryWorkMessage message) {
        try {
            switch (message.workType()) {
                case STATUS -> statusWorker.tick(message.discoveryUuid(), message.attempt());
                case DRAIN -> drainWorker.tick(message.discoveryUuid(), message.attempt());
                case PROCESS -> processWorker.tick(message.discoveryUuid(), message.attempt());
            }
        } catch (RuntimeException e) {
            logger
                    .error("Discovery {} tick failed for run {} (attempt {}); the agenda row retries when next due",
                            message.workType(), message.discoveryUuid(), message.attempt(), e);
        }
    }
}
