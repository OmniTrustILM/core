package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Component
public class OutboxSigningRecordWriter extends AbstractSigningRecordWriter {

    private final SigningRecordOutboxRepository repository;

    public OutboxSigningRecordWriter(SigningRecordOutboxRepository repository,
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
        timed("DEFERRED_DURABLE", () -> {
            SigningProfileVersion v = input.getVersion();
            SigningRecordOutbox row = new SigningRecordOutbox();
            row.setUuid(UUID.randomUUID());
            row.setName(input.getDisplayName());
            row.setSigningProfileUuid(input.getProfile().getUuid());
            row.setSigningProfileVersion(v.getVersion());
            row.setSigningTime(input.getSigningTime());
            if (v.isRecordRequestMetadata()) row.setRequestMetadataJson(input.getRequestMetadataJson());
            if (v.isRecordSignature())       row.setSignatureValue(input.getSignature());
            if (v.isRecordSignedDocument())  row.setSignedDocument(input.getSignedDocument());
            if (v.isRecordDtbs())            row.setDtbs(input.getDtbs());
            repository.save(row);
            metrics.outboxEnqueued().increment();
            metrics.created("DEFERRED_DURABLE").increment();
        });
    }
}
