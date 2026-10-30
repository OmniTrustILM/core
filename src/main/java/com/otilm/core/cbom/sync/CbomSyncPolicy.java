package com.otilm.core.cbom.sync;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.core.settings.SettingsCache;
import java.time.Duration;

import static com.otilm.core.util.NullUtil.defaultIfNull;

/**
 * The CBOM sync tunables, read from the platform settings rather than from the deployment.
 *
 * <p>
 * All eight are operator settings and live in the Settings UI beside the repository URL: under SaaS a tenant has no
 * other configuration surface, so a value that stayed in {@code application.yml} would be one an operator could not
 * reach. core#2268 moved the last four -- the page size, the asset-ingest kill switch, the ingest batch size and the
 * ingest retry window -- and deleted {@code CbomSyncProperties} with them, so nothing here is bound from yml or from an
 * environment variable any more.
 *
 * <p>
 * A run snapshots the policy once at its start: a setting changed mid-run applies to the next run on this node, never
 * to half of this one; another node picks the change up when its settings cache refreshes (every 30 seconds by
 * default). That is also what makes the kill switch take effect without a restart -- at the next run rather than at the
 * next deployment. Unset values take the defaults below, which the settings service also reports back, so a form shows
 * what the sync will use.
 *
 * <p>
 * The bounds are the contract's ({@code UtilsSettingsDto.MIN/MAX_CBOM_SYNC_*}): what the API refuses on the way in,
 * this refuses too, so a value can never be accepted by one and rejected by the other.
 *
 * @param overlap how far before the start of the last successful run each run re-lists
 * @param skippedRetryRuns how many later runs retry an entry that could not be stored
 * @param maxIngestDocuments how many documents one run ingests beyond its own feed pass
 * @param skipRetentionDays how many days after its last attempt a written-off entry stays listed before the retention
 * sweep removes its record; an entry still being retried is kept whatever its age
 * @param pageSize the {@code limit} sent with {@code GET /api/v1/bom}; pages are followed through {@code Link
 * rel="next"}, so it bounds one request rather than one run
 * @param assetIngestEnabled whether a run ingests cryptographic assets at all. The one switch that covers <b>both</b>
 * discovery paths -- the ingest of a document the run's own feed pass just stored, and the backlog pass over the rows
 * that still owe one. An ingest budget of 0 disables only the second, so it is not a kill switch: with it at zero a
 * newly stored CBOM still acquires {@code crypto_asset_source} rows
 * @param assetBatchSize how many assets one ingest transaction writes before committing, and the page size the
 * withdrawal path walks. It bounds how long one transaction holds the alias advisory lock and its row locks, not how
 * much work a run does
 * @param ingestRetryAfter how long a CBOM whose ingest is {@code IN_PROGRESS} or {@code FAILED} is left alone before a
 * run offers it again. Measured from the start of the attempt, not from its last sign of life: the ingest stamps
 * {@code asset_sync_attempted_at} when it claims the CBOM and again when it finishes, and not in between. So this has
 * to exceed the longest single document the deployment expects to ingest, or a second run takes over one that is still
 * being written -- which costs a wasted slot and a reset claim rather than a corrupt row, because the cluster lock
 * still admits one writer at a time
 */
public record CbomSyncPolicy(Duration overlap, int skippedRetryRuns, int maxIngestDocuments, int skipRetentionDays,
        int pageSize, boolean assetIngestEnabled, int assetBatchSize, Duration ingestRetryAfter) {

    /**
     * Covers the clock skew between Core and the repository's object store plus the longest upload (S3 stamps a
     * multipart upload with its initiation time); the CBOM Repository documents 60 s as that total.
     */
    public static final int DEFAULT_OVERLAP_SECONDS = 60;
    public static final Duration DEFAULT_OVERLAP = Duration.ofSeconds(DEFAULT_OVERLAP_SECONDS);
    public static final int DEFAULT_SKIPPED_RETRY_RUNS = 3;
    public static final int DEFAULT_MAX_INGEST_DOCUMENTS = 50;
    /** A quarter: long enough for an operator to notice a written-off document, short enough to bound the table. */
    public static final int DEFAULT_SKIP_RETENTION_DAYS = 90;
    public static final int DEFAULT_PAGE_SIZE = 1000;
    public static final boolean DEFAULT_ASSET_INGEST_ENABLED = true;
    public static final int DEFAULT_ASSET_BATCH_SIZE = 100;
    public static final int DEFAULT_INGEST_RETRY_AFTER_SECONDS = 1800;
    public static final Duration DEFAULT_INGEST_RETRY_AFTER = Duration.ofSeconds(DEFAULT_INGEST_RETRY_AFTER_SECONDS);

    public static final CbomSyncPolicy DEFAULTS = new CbomSyncPolicy(DEFAULT_OVERLAP, DEFAULT_SKIPPED_RETRY_RUNS,
            DEFAULT_MAX_INGEST_DOCUMENTS, DEFAULT_SKIP_RETENTION_DAYS, DEFAULT_PAGE_SIZE, DEFAULT_ASSET_INGEST_ENABLED,
            DEFAULT_ASSET_BATCH_SIZE, DEFAULT_INGEST_RETRY_AFTER);

    public CbomSyncPolicy {
        if (overlap == null || overlap.isNegative()) {
            throw new IllegalArgumentException("the CBOM sync overlap must be a non-negative duration, was " + overlap);
        }
        if (overlap.compareTo(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS)) > 0) {
            throw new IllegalArgumentException("the CBOM sync overlap must not exceed %d seconds, was %s"
                    .formatted(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS, overlap));
        }
        if (skippedRetryRuns < 0 || skippedRetryRuns > UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS) {
            throw new IllegalArgumentException("the CBOM sync retry budget must be within 0..%d runs, was %d"
                    .formatted(UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS, skippedRetryRuns));
        }
        if (maxIngestDocuments < 0 || maxIngestDocuments > UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS) {
            throw new IllegalArgumentException("the CBOM sync ingest budget must be within 0..%d documents, was %d"
                    .formatted(UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS, maxIngestDocuments));
        }
        if (skipRetentionDays < UtilsSettingsDto.MIN_CBOM_SYNC_SKIP_RETENTION_DAYS
                || skipRetentionDays > UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS) {
            throw new IllegalArgumentException("the CBOM sync skip retention must be within %d..%d days, was %d"
                    .formatted(UtilsSettingsDto.MIN_CBOM_SYNC_SKIP_RETENTION_DAYS,
                            UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS, skipRetentionDays));
        }
        if (pageSize < UtilsSettingsDto.MIN_CBOM_SYNC_PAGE_SIZE
                || pageSize > UtilsSettingsDto.MAX_CBOM_SYNC_PAGE_SIZE) {
            throw new IllegalArgumentException("the CBOM sync page size must be within %d..%d, was %d"
                    .formatted(UtilsSettingsDto.MIN_CBOM_SYNC_PAGE_SIZE, UtilsSettingsDto.MAX_CBOM_SYNC_PAGE_SIZE,
                            pageSize));
        }
        if (assetBatchSize < UtilsSettingsDto.MIN_CBOM_SYNC_ASSET_BATCH_SIZE
                || assetBatchSize > UtilsSettingsDto.MAX_CBOM_SYNC_ASSET_BATCH_SIZE) {
            throw new IllegalArgumentException("the CBOM sync asset batch size must be within %d..%d, was %d"
                    .formatted(UtilsSettingsDto.MIN_CBOM_SYNC_ASSET_BATCH_SIZE,
                            UtilsSettingsDto.MAX_CBOM_SYNC_ASSET_BATCH_SIZE, assetBatchSize));
        }
        if (ingestRetryAfter == null || ingestRetryAfter.isNegative()) {
            throw new IllegalArgumentException(
                    "the CBOM sync ingest retry window must be a non-negative duration, was " + ingestRetryAfter);
        }
        if (ingestRetryAfter
                .compareTo(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS)) > 0) {
            throw new IllegalArgumentException("the CBOM sync ingest retry window must not exceed %d seconds, was %s"
                    .formatted(UtilsSettingsDto.MAX_CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS, ingestRetryAfter));
        }
    }

    /** The first failed attempt plus the configured retries: the attempt count at which an entry is written off. */
    public int maxAttempts() {
        return 1 + skippedRetryRuns;
    }

    /**
     * From the platform utils settings as the cache holds them; a missing section or an unset value takes its default.
     * The API validates the bounds on the way in and the settings service reads a stored value outside them as the
     * default, so nothing the settings service puts in the cache can make this throw.
     */
    public static CbomSyncPolicy fromSettings(UtilsSettingsDto utils) {
        if (utils == null) {
            return DEFAULTS;
        }
        return new CbomSyncPolicy(
                Duration.ofSeconds(defaultIfNull(utils.getCbomSyncOverlapSeconds(), DEFAULT_OVERLAP_SECONDS)),
                defaultIfNull(utils.getCbomSyncSkippedRetryRuns(), DEFAULT_SKIPPED_RETRY_RUNS),
                defaultIfNull(utils.getCbomSyncMaxIngestDocuments(), DEFAULT_MAX_INGEST_DOCUMENTS),
                defaultIfNull(utils.getCbomSyncSkipRetentionDays(), DEFAULT_SKIP_RETENTION_DAYS),
                defaultIfNull(utils.getCbomSyncPageSize(), DEFAULT_PAGE_SIZE),
                defaultIfNull(utils.getCbomSyncAssetIngestEnabled(), DEFAULT_ASSET_INGEST_ENABLED),
                defaultIfNull(utils.getCbomSyncAssetBatchSize(), DEFAULT_ASSET_BATCH_SIZE),
                Duration
                        .ofSeconds(defaultIfNull(utils.getCbomSyncIngestRetryAfterSeconds(),
                                DEFAULT_INGEST_RETRY_AFTER_SECONDS)));
    }

    /**
     * From the settings cache as it stands: the defaults before the platform settings were ever read, which is how a
     * scheduled job starting ahead of the first cache fill reads them.
     */
    public static CbomSyncPolicy fromSettingsCache() {
        PlatformSettingsDto platform = SettingsCache.getSettings(SettingsSection.PLATFORM);
        return platform == null ? DEFAULTS : fromSettings(platform.getUtils());
    }
}
