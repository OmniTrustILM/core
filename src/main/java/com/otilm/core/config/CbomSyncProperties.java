package com.otilm.core.config;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;

/**
 * Tuning for the CBOM header sync against cbom-repository, bound from {@code cbom.sync.*} and validated at startup.
 *
 * <p>
 * These are deployment-time protocol and lock parameters, not operator settings: the page size is bounded by the
 * repository's contract, the kill switch is a deployment decision, and the batch size and the retry window govern how
 * long an ingest holds its locks.
 *
 * <p>
 * The operator policy -- the re-list overlap, the retry budget for documents that could not be stored and the per-run
 * ingest budget -- is not here: it is a platform setting, read at the start of each run into {@code CbomSyncPolicy}.
 *
 * @param pageSize the {@code limit} sent with {@code GET /api/v1/bom}; 1..1000 per the contract, 1000 by default
 * @param assetIngestEnabled whether a run ingests cryptographic assets at all; true by default. The one switch that
 * covers <b>both</b> discovery paths -- the inline ingest of a document the run's own feed pass just stored, and the
 * backlog pass over the rows that still owe one. An ingest budget ({@code cbomSyncMaxIngestDocuments}) of 0 disables
 * only the second, so it is not a kill switch: with it at zero a newly stored CBOM still acquires
 * {@code crypto_asset_source} rows, and a CBOM that has them cannot be deleted through the API until the deletion
 * lifecycle lands. Turning this off is what stops that spreading, and it is why the value carries a deploy-time
 * override
 * @param assetBatchSize how many assets one ingest transaction writes before committing; 100 by default. It bounds how
 * long an ingest holds the alias advisory lock and its row locks, not how much work a run does
 * @param ingestRetryAfter how long a CBOM whose ingest is {@code IN_PROGRESS} or {@code FAILED} is left alone before a
 * run offers it again; 30 minutes by default. Measured from the start of the attempt, not from its last sign of life:
 * the ingest stamps {@code asset_sync_attempted_at} when it claims the CBOM and again when it finishes, and not in
 * between. So this has to exceed the longest single document the deployment expects to ingest, or a second run takes
 * over one that is still being written -- which costs a wasted slot and a reset claim rather than a corrupt row,
 * because the cluster lock still admits one writer at a time.
 */
@ConfigurationProperties(prefix = "cbom.sync")
public record CbomSyncProperties(@DefaultValue("1000") int pageSize, @DefaultValue("true") boolean assetIngestEnabled,
        @DefaultValue("100") int assetBatchSize,
        @DefaultValue("30m") @DurationUnit(ChronoUnit.SECONDS) Duration ingestRetryAfter) {

    public static final int MIN_PAGE_SIZE = 1;
    public static final int MAX_PAGE_SIZE = 1000;

    public CbomSyncProperties {
        if (pageSize < MIN_PAGE_SIZE || pageSize > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("cbom.sync.page-size must be within %d..%d, was %d"
                    .formatted(MIN_PAGE_SIZE, MAX_PAGE_SIZE, pageSize));
        }
        if (assetBatchSize < 1) {
            throw new IllegalArgumentException("cbom.sync.asset-batch-size must be positive, was " + assetBatchSize);
        }
        if (ingestRetryAfter == null || ingestRetryAfter.isNegative()) {
            throw new IllegalArgumentException(
                    "cbom.sync.ingest-retry-after must be a non-negative duration, was " + ingestRetryAfter);
        }
    }
}
