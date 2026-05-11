package com.czertainly.core.signing.record;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

@Component
public class SigningRecordMetrics {

    private final MeterRegistry registry;

    public SigningRecordMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public Counter created(String mode) {
        return Counter.builder("signing_record.created.total").tag("mode", mode).register(registry);
    }

    public Counter skippedNoContentPolicy() {
        return Counter.builder("signing_record.skipped_no_content_policy.total").register(registry);
    }

    public Counter outboxEnqueued() {
        return registry.counter("signing_record.outbox.enqueued.total");
    }

    public Counter outboxDrained() {
        return registry.counter("signing_record.outbox.drained.total");
    }

    public Counter outboxFailed() {
        return registry.counter("signing_record.outbox.failed.total");
    }

    public Counter outboxPoison() {
        return registry.counter("signing_record.outbox.poison.total");
    }

    public Counter bestEffortDropped(String reason) {
        return Counter.builder("signing_record.best_effort.dropped.total").tag("reason", reason).register(registry);
    }

    public Counter retentionDeleted() {
        return registry.counter("signing_record.retention.deleted.total");
    }

    public Counter retrievalDeleted() {
        return registry.counter("signing_record.delete_after_retrieval.deleted.total");
    }

    public Counter retrievalFailed() {
        return registry.counter("signing_record.delete_after_retrieval.failed.total");
    }

    public Timer writeDuration(String mode) {
        return Timer.builder("signing_record.write.duration_ms").tag("mode", mode).register(registry);
    }

    public MeterRegistry registry() {
        return registry;
    }
}
