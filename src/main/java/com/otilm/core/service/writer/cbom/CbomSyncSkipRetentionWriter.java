package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import java.time.OffsetDateTime;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The retention sweep's batch delete: one short transaction per batch.
 *
 * <p>
 * A separate bean rather than a method on {@code CbomSyncSkipWriter}, because {@code TransactionalBoundaryArchTest}
 * Rule D requires every public method of a {@code @Service} in this package to be {@code REQUIRED}, and this one must
 * not be: a {@code REQUIRED} delete would join the sweep's lock transaction and hold every row lock until the sweep
 * ended. {@code CryptoAssetPqcVerdictWriter} makes the same choice for the same reason, and is a {@code @Component} for
 * it too.
 */
@Component
public class CbomSyncSkipRetentionWriter {

    private final CbomSyncSkipRepository repository;

    public CbomSyncSkipRetentionWriter(CbomSyncSkipRepository repository) {
        this.repository = repository;
    }

    /** @return how many written-off rows older than the cutoff this batch removed, at most {@code batchSize} */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteWrittenOffBatch(OffsetDateTime cutoff, int batchSize) {
        return repository.deleteWrittenOffBefore(cutoff, batchSize);
    }
}
