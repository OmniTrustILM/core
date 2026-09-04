package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.writer.cbom.CryptoAssetPqcVerdictWriter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Restamps every asset whose verdict predates the shipped rule-set generation, in batches, so a rule-set bump reaches
 * the inventory instead of waiting for the next time each row happens to be re-ingested.
 *
 * <p>
 * <b>The lock is held for the whole sweep; the row locks are not.</b> This method's transaction exists to hold the
 * transaction-scoped advisory lock, which is what keeps one node sweeping at a time. Every write goes through
 * {@link CryptoAssetPqcVerdictWriter}'s {@code REQUIRES_NEW} batch method, so each batch commits and releases its row
 * locks and WAL before the next is read. The per-sweep batch cap bounds how long the outer transaction stays open -- a
 * long hold keeps a connection idle-in-transaction and pins the vacuum horizon -- so a large backlog clears over
 * several sweeps rather than one long run. Note the scheduler path opens a transaction above this one, and that one is
 * not capped by anything here, which is a second reason to keep the cap modest.
 *
 * <p>
 * <b>Failures are per row, and never retried inside the same sweep.</b> A row whose evaluation throws is counted,
 * logged once and skipped. Retrying it would be the one thing that can stop the sweep advancing, because the cursor
 * moves past whatever it has read; a row that fails every sweep is a bug to find in the logs, not a reason to strand
 * every row behind it.
 */
@Slf4j
@Component
public class PqcVerdictSweeper {

    /** The keyset cursor's origin. Ordering is by uuid, so the nil uuid precedes every real row. */
    private static final UUID BEFORE_FIRST = new UUID(0L, 0L);

    private final CryptoAssetRepository assetRepository;
    private final CryptoAssetPqcVerdictWriter verdictWriter;
    private final PqcEvaluator evaluator;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final MeterRegistry meterRegistry;
    private final int batchSize;
    private final int maxBatchesPerSweep;

    public PqcVerdictSweeper(CryptoAssetRepository assetRepository, CryptoAssetPqcVerdictWriter verdictWriter,
            PqcEvaluator evaluator, ClusterOperationSynchronizer clusterSynchronizer, MeterRegistry meterRegistry,
            PqcSweepProperties properties) {
        this.assetRepository = assetRepository;
        this.verdictWriter = verdictWriter;
        this.evaluator = evaluator;
        this.clusterSynchronizer = clusterSynchronizer;
        this.meterRegistry = meterRegistry;
        this.batchSize = properties.batchSize();
        this.maxBatchesPerSweep = properties.maxBatchesPerSweep();
    }

    /**
     * @return what the sweep did, for the scheduled job's history entry, or {@link SweepOutcome#skipped} when there was
     * nothing to do or another node was already doing it
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public SweepOutcome sweep() {
        if (maxBatchesPerSweep <= 0) {
            log.debug("PQC verdict sweep disabled: max-batches-per-sweep is {}", maxBatchesPerSweep);
            return SweepOutcome.skipped();
        }
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.CRYPTO_ASSET_PQC_SWEEP)) {
            log.debug("PQC verdict sweep skipped: another instance holds the lock");
            return SweepOutcome.skipped();
        }
        meterRegistry.counter("crypto_asset.pqc_sweep").increment();

        UUID cursor = BEFORE_FIRST;
        int evaluated = 0;
        int written = 0;
        int failed = 0;
        int batches = 0;
        try {
            List<PqcStaleVerdictRow> rows;
            do {
                rows = assetRepository.findStaleVerdictRows(PqcRuleset.VERSION, cursor, PageRequest.of(0, batchSize));
                if (rows.isEmpty()) {
                    break;
                }
                cursor = rows.get(rows.size() - 1).uuid();
                List<PqcVerdictWrite> writes = new ArrayList<>(rows.size());
                for (PqcStaleVerdictRow row : rows) {
                    try {
                        writes.add(new PqcVerdictWrite(row.uuid(), evaluate(row)));
                        evaluated++;
                    } catch (RuntimeException e) {
                        failed++;
                        // The uuid, never the identity key: this line reaches an operator's log aggregator.
                        log
                                .warn("PQC verdict evaluation failed for cryptographic asset {}; skipping it",
                                        row.uuid(), e);
                    }
                }
                written += verdictWriter.applyStaleBatch(writes, PqcRuleset.VERSION);
                batches++;
            } while (rows.size() == batchSize && batches < maxBatchesPerSweep);

            if (rows.size() == batchSize && batches >= maxBatchesPerSweep) {
                log
                        .debug("PQC verdict sweep stopped at the per-sweep cap of {} batch(es); the remaining stale rows clear on the next sweep",
                                maxBatchesPerSweep);
            }
        } catch (RuntimeException e) {
            meterRegistry.counter("crypto_asset.pqc_sweep.failed").increment();
            log.warn("PQC verdict sweep aborted after writing {} verdict(s); will retry next interval", written, e);
        }
        if (written > 0) {
            meterRegistry.counter("crypto_asset.pqc_sweep.written").increment(written);
            log.info("PQC verdict sweep restamped {} cryptographic asset(s)", written);
        }
        return new SweepOutcome(true, evaluated, written, failed, batches);
    }

    private PqcDecision evaluate(PqcStaleVerdictRow row) {
        JsonNode merged = row.mergedCryptoProperties() == null
                ? null
                : ObjectMapperFactory.jsonColumn().valueToTree(row.mergedCryptoProperties());
        return evaluator
                .evaluate(evaluator.fromStoredRow(row.fields(), merged), PqcEvaluator.nistQuantumSecurityLevel(merged));
    }

    /**
     * What one sweep did.
     *
     * @param ran false when the sweep was disabled or another node held the lock, which the scheduled job reports as a
     * skip rather than as a successful run that happened to do nothing
     */
    public record SweepOutcome(boolean ran, int evaluated, int written, int failed, int batches) {

        static SweepOutcome skipped() {
            return new SweepOutcome(false, 0, 0, 0, 0);
        }
    }
}
