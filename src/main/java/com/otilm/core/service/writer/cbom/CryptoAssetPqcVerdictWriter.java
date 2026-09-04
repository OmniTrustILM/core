package com.otilm.core.service.writer.cbom;

import com.otilm.core.cbom.asset.JsonColumnText;
import com.otilm.core.cbom.pqc.PqcVerdictWrite;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The re-evaluation sweep's batch write path: one short transaction per batch, committed and released before the next
 * batch is read.
 *
 * <p>
 * <b>Why this is its own bean rather than a method on {@link CryptoAssetWriter}.</b> Two architecture rules make that
 * shape impossible, and both of them are load-bearing rather than stylistic.
 * {@code IdentityRulesetStampArchTest.theAssetWriterIsStillUnreachableFromProduction} fails the build if <em>any</em>
 * production class depends on {@code CryptoAssetWriter} -- it is the tripwire that forces
 * {@code IdentityRuleset.VERSION} to be bumped when ingest is finally wired, and a sweeper reaching for that bean would
 * spring it years early for a reason it was not built to catch. And {@code TransactionalBoundaryArchTest} Rule D
 * requires every public method of a {@code @Service} in this package to be effectively {@code REQUIRED}, which a
 * batch-scoped {@code REQUIRES_NEW} method is not. {@code SigningRecordWriter.deleteExpiredBatch} is the shape copied
 * here, and it escapes Rule D only because that bean is a {@code @Component} -- so this one is too.
 *
 * <p>
 * <b>Why {@code REQUIRES_NEW} and not {@code REQUIRED}.</b> The sweep holds a transaction-scoped advisory lock for its
 * whole run, so a {@code REQUIRED} write would join that transaction and keep every row lock it took until the sweep
 * ended. Suspending it and committing per batch is what lets row locks and WAL release incrementally while the outer
 * transaction keeps the one-sweeper-per-cluster guarantee.
 */
@Component
public class CryptoAssetPqcVerdictWriter {

    private final CryptoAssetRepository assetRepository;

    public CryptoAssetPqcVerdictWriter(CryptoAssetRepository assetRepository) {
        this.assetRepository = assetRepository;
    }

    /**
     * Writes a batch of verdicts, skipping any row a fresher verdict reached first.
     *
     * @return how many rows were actually written, which is below {@code batch.size()} whenever ingest overtook the
     * sweep between its read and this write -- a normal outcome, not an error
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int applyStaleBatch(List<PqcVerdictWrite> batch, int rulesetVersion) {
        int written = 0;
        for (PqcVerdictWrite write : batch) {
            written += assetRepository
                    .applyPqcVerdictIfStale(write.assetUuid(), write.decision().verdict().name(),
                            write.decision().ruleId(), write.decision().reason(), rulesetVersion,
                            JsonColumnText.render(write.decision().evaluatedFields()));
        }
        return written;
    }
}
