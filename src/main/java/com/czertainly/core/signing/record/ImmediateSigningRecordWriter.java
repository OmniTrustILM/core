package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
public class ImmediateSigningRecordWriter extends AbstractSigningRecordWriter {

    private final SigningRecordRepository repository;

    public ImmediateSigningRecordWriter(SigningRecordRepository repository,
                                        SigningRecordMetrics metrics) {
        super(metrics);
        this.repository = repository;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public void record(SigningRecordInput input) {
        if (!hasAnyRecordableContent(input.getVersion())) {
            metrics.skippedNoContentPolicy().increment();
            return;
        }
        timed("IMMEDIATE", () -> {
            SigningRecord r = buildSigningRecord(input);
            r.setSigningProfile(input.getProfile());
            repository.save(r);
            metrics.created("IMMEDIATE").increment();
        });
    }
}
