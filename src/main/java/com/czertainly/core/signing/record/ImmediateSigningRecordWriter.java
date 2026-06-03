package com.czertainly.core.signing.record;

import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
public class ImmediateSigningRecordWriter implements SigningRecordWriter {

    private final SigningRecordRepository repository;
    private final SigningRecordMapper mapper;
    private final SigningRecordMetrics metrics;

    public ImmediateSigningRecordWriter(SigningRecordRepository repository,
                                        SigningRecordMapper mapper,
                                        SigningRecordMetrics metrics) {
        this.repository = repository;
        this.mapper = mapper;
        this.metrics = metrics;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public void record(SigningRecordInput input) {
        if (!SigningRecordPolicy.hasAnyRecordableContent(input.getSigningProfile().recordPolicy())) {
            metrics.skippedNoContentPolicy().increment();
            return;
        }
        metrics.timed("IMMEDIATE", () -> {
            try {
                repository.save(mapper.toRecord(input));
                metrics.created("IMMEDIATE").increment();
            } catch (RuntimeException e) {
                metrics.persistFailed("IMMEDIATE").increment();
                throw e;
            }
        });
    }
}
