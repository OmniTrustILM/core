package com.otilm.core.cbom.ingest;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class InventoryEventOutboxScheduler {

    private final InventoryEventOutboxDispatcher dispatcher;

    public InventoryEventOutboxScheduler(InventoryEventOutboxDispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    @Scheduled(fixedDelayString = "${cbom.inventory-event-outbox-flush-interval-ms:60000}")
    public void dispatchReady() {
        dispatcher.dispatchReady();
    }
}
