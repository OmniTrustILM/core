package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.writer.cbom.CryptoAssetPqcVerdictWriter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Restamps every asset whose verdict predates {@link PqcRuleset#VERSION} or the row it describes, in batches.
 *
 * <p>
 * This transaction exists to hold the advisory lock, not to write: every write goes through
 * {@link CryptoAssetPqcVerdictWriter}'s {@code REQUIRES_NEW} batch, so row locks release per batch while the lock keeps
 * one node sweeping. The cap bounds how long this transaction stays open; the scheduler opens one above it that nothing
 * here caps.
 */
@Slf4j
@Component
public class PqcVerdictSweeper {

    /** Ordering is by uuid, so the nil uuid precedes every row. */
    private static final UUID BEFORE_FIRST = new UUID(0L, 0L);

    /** Shared: building one costs 736 us against 4 us reused, inside the transaction that holds the lock. */
    private static final ObjectMapper JSON_COLUMN = ObjectMapperFactory.jsonColumn();

    /**
     * What a row gets when evaluation throws: stamped current so the sweep moves past it instead of finding it at the
     * head of the work list forever. No evidence, because the inputs are what failed.
     */
    private static final PqcDecision EVALUATION_FAILED = new PqcDecision(PqcVerdict.UNKNOWN, "EVALUATION-FAILED",
            "The rule set could not be evaluated against this asset's recorded properties", Map.of());

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

    /** @return what the sweep did, for the job's history entry */
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

        Tally tally = new Tally();
        UUID cursor = BEFORE_FIRST;
        try {
            List<PqcStaleVerdictRow> rows;
            do {
                rows = assetRepository.staleVerdictRows(PqcRuleset.VERSION, cursor, batchSize);
                if (rows.isEmpty()) {
                    break;
                }
                cursor = rows.get(rows.size() - 1).uuid();
                sweepBatch(rows, tally);
            } while (rows.size() == batchSize && tally.batches < maxBatchesPerSweep);

            if (rows.size() == batchSize && tally.batches >= maxBatchesPerSweep) {
                log
                        .debug("PQC verdict sweep stopped at the per-sweep cap of {} batch(es); the remaining stale rows clear on the next sweep",
                                maxBatchesPerSweep);
            }
        } catch (RuntimeException e) {
            meterRegistry.counter("crypto_asset.pqc_sweep.aborted").increment();
            log
                    .warn("PQC verdict sweep aborted after writing {} verdict(s); will retry next interval",
                            tally.written, e);
            tally.aborted = true;
        }
        if (tally.written > 0) {
            meterRegistry.counter("crypto_asset.pqc_sweep.written").increment(tally.written);
            log.info("PQC verdict sweep restamped {} cryptographic asset(s)", tally.written);
        }
        return tally.outcome();
    }

    /** One page of the work list: evaluate every row, then write the page in one transaction. */
    private void sweepBatch(List<PqcStaleVerdictRow> rows, Tally tally) {
        List<PqcVerdictWrite> writes = new ArrayList<>(rows.size());
        Set<UUID> unevaluable = new HashSet<>();
        for (PqcStaleVerdictRow row : rows) {
            PqcDecision decision = decideOrRecordFailure(row);
            if (decision == EVALUATION_FAILED) {
                unevaluable.add(row.uuid());
            }
            writes.add(new PqcVerdictWrite(row.uuid(), row.rowVersion(), decision));
        }
        tally.read += rows.size();
        tally.batches++;

        for (UUID landed : write(writes, tally)) {
            tally.written++;
            if (unevaluable.contains(landed)) {
                tally.unevaluated++;
            }
        }
    }

    /**
     * The batch, retried one row per transaction if it rolls back. A batch shares one transaction, so any row the
     * database refuses takes the whole page with it -- and the cursor restarts at the nil uuid every sweep, so a
     * persistent refusal would be reached first on every run and nothing behind it would ever be written.
     *
     * @return which rows landed
     */
    private List<UUID> write(List<PqcVerdictWrite> writes, Tally tally) {
        try {
            return verdictWriter.applyStaleBatch(writes, PqcRuleset.VERSION);
        } catch (RuntimeException e) {
            meterRegistry.counter("crypto_asset.pqc_sweep.batch_retried").increment();
            log
                    .warn("PQC verdict batch write rolled back; retrying its {} row(s) one transaction at a time",
                            writes.size(), e);
        }
        List<UUID> landed = new ArrayList<>(writes.size());
        for (PqcVerdictWrite write : writes) {
            try {
                if (verdictWriter.applyStaleRow(write, PqcRuleset.VERSION)) {
                    landed.add(write.assetUuid());
                }
            } catch (RuntimeException e) {
                tally.writeFailures++;
                meterRegistry.counter("crypto_asset.pqc_sweep.write_failed").increment();
                // The uuid, never the identity key: this line reaches an operator's log aggregator.
                log
                        .warn("PQC verdict write failed for cryptographic asset {}; it stays on the work list",
                                write.assetUuid(), e);
            }
        }
        return landed;
    }

    /**
     * The sentinel is returned by identity, so the caller can tell a stamped failure from a verdict without inspecting
     * it -- a row may legitimately evaluate to the same verdict and rule id that a failure records.
     */
    private PqcDecision decideOrRecordFailure(PqcStaleVerdictRow row) {
        try {
            return evaluate(row);
        } catch (RuntimeException e) {
            meterRegistry.counter("crypto_asset.pqc_sweep.evaluation_failed").increment();
            // The uuid, never the identity key: this line reaches an operator's log aggregator.
            log
                    .warn("PQC verdict evaluation failed for cryptographic asset {}; recording it as unevaluated",
                            row.uuid(), e);
            return EVALUATION_FAILED;
        }
    }

    private PqcDecision evaluate(PqcStaleVerdictRow row) {
        JsonNode merged = mergedPayload(row);
        return evaluator
                .evaluate(evaluator.fromStoredRow(row.fields(), merged), PqcEvaluator.nistQuantumSecurityLevel(merged));
    }

    private static JsonNode mergedPayload(PqcStaleVerdictRow row) {
        if (row.mergedCryptoPropertiesJson() == null) {
            return null;
        }
        try {
            return JSON_COLUMN.readTree(row.mergedCryptoPropertiesJson());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The stored merged payload is not readable as JSON", e);
        }
    }

    /** Mutable while one sweep runs; {@link #outcome()} is what leaves the class. */
    private static final class Tally {

        private int read;
        private int written;
        private int unevaluated;
        private int writeFailures;
        private int batches;
        private boolean aborted;

        private SweepOutcome outcome() {
            return new SweepOutcome(true, aborted, read, written, unevaluated, writeFailures, batches);
        }
    }

    /**
     * @param ran false when disabled or another node held the lock, which is a skip rather than an empty success
     * @param read rows taken off the work list, whatever became of them
     * @param written rows whose verdict landed
     * @param unevaluated rows the rule set threw on <em>and</em> whose {@code EVALUATION-FAILED} stamp landed, so
     * saying they were recorded is true of exactly these
     * @param writeFailures rows whose own write transaction failed; they stay on the work list
     */
    public record SweepOutcome(boolean ran, boolean aborted, int read, int written, int unevaluated, int writeFailures,
            int batches) {

        static SweepOutcome skipped() {
            return new SweepOutcome(false, false, 0, 0, 0, 0, 0);
        }

        /** Rows the guard refused: someone else wrote them first, or they are no longer stale. Retried next sweep. */
        public int refused() {
            return read - written - writeFailures;
        }
    }
}
