package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.SigningRecordRetentionSweeper;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Component
public class SigningRecordDeletionWriter {

    private final SigningRecordRepository repository;

    public SigningRecordDeletionWriter(SigningRecordRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void deleteByUuid(UUID uuid) {
        repository.deleteByUuid(uuid);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteExpiredBatch(int limit) {
        return repository.deleteExpiredByRetention(limit);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteRetrievedAndFlaggedBatch(int limit) {
        return repository.deleteRetrievedAndFlagged(limit);
    }
}
