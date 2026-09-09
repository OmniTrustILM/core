package com.otilm.core.service.writer.cbom;

import com.otilm.core.cbom.asset.JsonColumnText;
import com.otilm.core.cbom.pqc.PqcVerdictWrite;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The sweep's batch write: one short transaction per batch.
 *
 * <p>
 * A separate bean because two rules forbid putting this on {@code CryptoAssetWriter}.
 * {@code IdentityRulesetStampArchTest} fails if any production class depends on that bean -- it is the tripwire that
 * forces {@code IdentityRuleset.VERSION} to move when ingest is wired. {@code TransactionalBoundaryArchTest} Rule D
 * requires every public method of a {@code @Service} here to be {@code REQUIRED}. {@code SigningRecordWriter} escapes
 * Rule D only by being a {@code @Component}, so this is one too.
 *
 * <p>
 * {@code REQUIRES_NEW} because a {@code REQUIRED} write would join the sweep's lock transaction and hold every row lock
 * until the sweep ended.
 */
@Component
public class CryptoAssetPqcVerdictWriter {

    private final CryptoAssetRepository assetRepository;

    public CryptoAssetPqcVerdictWriter(CryptoAssetRepository assetRepository) {
        this.assetRepository = assetRepository;
    }

    /**
     * @return which rows were written, in batch order -- fewer than were offered when another writer reached a row
     * after the sweep read it, which is normal. The identities rather than a count, because the sweep has to know
     * whether the row it stamped as unevaluable is the one that landed before it can report having recorded it.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public List<UUID> applyStaleBatch(List<PqcVerdictWrite> batch, int rulesetVersion) {
        List<UUID> written = new ArrayList<>(batch.size());
        for (PqcVerdictWrite write : batch) {
            if (apply(write, rulesetVersion) == 1) {
                written.add(write.assetUuid());
            }
        }
        return written;
    }

    /**
     * One row in one transaction, for retrying a batch that rolled back. Without it a single row the database refuses
     * -- a constraint the rules have drifted past, a deadlock -- takes its whole batch down, and since the cursor
     * restarts at the nil uuid every sweep, that batch is reached first on every run and starves every stale row
     * behind it.
     *
     * @return true if the row was written, false if the guard refused it
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean applyStaleRow(PqcVerdictWrite write, int rulesetVersion) {
        return apply(write, rulesetVersion) == 1;
    }

    private int apply(PqcVerdictWrite write, int rulesetVersion) {
        return assetRepository
                .applyPqcVerdictIfStale(write.assetUuid(), write.rowVersion(), write.decision().verdict().name(),
                        write.decision().ruleId(), write.decision().reason(), rulesetVersion,
                        JsonColumnText.render(write.decision().evaluatedFields()));
    }
}
