package com.czertainly.core.signing.record;

import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
public class SigningRecordOutboxGauges {

    private final MeterRegistry registry;
    private final SigningRecordOutboxRepository repository;
    private final int poisonThreshold;

    public SigningRecordOutboxGauges(MeterRegistry registry, SigningRecordOutboxRepository repository,
                                     SigningRecordOutboxProperties properties) {
        this.registry = registry;
        this.repository = repository;
        this.poisonThreshold = properties.poisonThreshold();
    }

    @PostConstruct
    public void register() {
        Gauge.builder("signing_record.outbox.depth", repository, r -> (double) r.count())
                .register(registry);
        Gauge.builder("signing_record.outbox.lag_seconds", repository, r ->
                        r.findOldestSigningTimeBelowPoisonThreshold(poisonThreshold)
                                .map(t -> (double) Duration.between(t, Instant.now()).toSeconds())
                                .orElse(0.0))
                .register(registry);
        Gauge.builder("signing_record.outbox.poisoned", repository, r -> (double) r.countPoisoned(poisonThreshold))
                .register(registry);
    }
}
