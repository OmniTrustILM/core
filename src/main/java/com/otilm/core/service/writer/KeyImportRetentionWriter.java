package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.KeyImportRepository;
import java.time.OffsetDateTime;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Deletes the finished import attempts past their retention, each batch in a transaction of its own, so a batch holds
 * its rows only while it runs. It is a component of its own because the methods of {@link KeyImportWriter} join their
 * caller's transaction, and a batch must not.
 */
@Component
public class KeyImportRetentionWriter {

    private final KeyImportRepository keyImportRepository;

    public KeyImportRetentionWriter(KeyImportRepository keyImportRepository) {
        this.keyImportRepository = keyImportRepository;
    }

    /**
     * Deletes the attempts that completed, failed or were compensated before the cutoff, at most {@code limit} of them.
     *
     * @return how many attempts were deleted
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteFinishedBefore(OffsetDateTime cutoff, int limit) {
        return keyImportRepository.deleteFinishedBefore(cutoff, limit);
    }
}
