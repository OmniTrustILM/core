package com.otilm.core.cbom.sync;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.core.settings.SettingsCache;
import java.time.Duration;

import static com.otilm.core.util.NullUtil.defaultIfNull;

/**
 * The operator's half of the CBOM sync tunables, read from the platform settings once per run.
 *
 * <p>
 * Four values are policy rather than deploy-time plumbing -- how far back a run re-lists, how many later runs retry a
 * document that could not be stored, how many documents a run ingests beyond its own feed pass, and how long a document
 * the sync gave up on stays listed -- so they live in the Settings UI beside the repository URL, not in
 * {@code application.yml}. A run snapshots them once at its start: a setting changed mid-run applies to the next run on
 * this node, never to half of this one; another node picks the change up when its settings cache refreshes (every 30
 * seconds by default). Unset values take the defaults below, which the settings service also reports back, so a form
 * shows what the sync will use.
 *
 * <p>
 * The bounds are the contract's ({@code UtilsSettingsDto.MAX_CBOM_SYNC_*}): what the API refuses on the way in, this
 * refuses too, so a value can never be accepted by one and rejected by the other.
 *
 * <p>
 * The other four values ({@code CbomSyncProperties}: the page size, the asset-ingest kill switch, the ingest batch size
 * and the ingest retry window) stay deploy-time on purpose; core#2249 carries the ruling.
 */
public record CbomSyncPolicy(Duration overlap, int skippedRetryRuns, int maxIngestDocuments, int skipRetentionDays) {

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

    public static final CbomSyncPolicy DEFAULTS = new CbomSyncPolicy(DEFAULT_OVERLAP, DEFAULT_SKIPPED_RETRY_RUNS,
            DEFAULT_MAX_INGEST_DOCUMENTS, DEFAULT_SKIP_RETENTION_DAYS);

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
        if (skipRetentionDays < 1 || skipRetentionDays > UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS) {
            throw new IllegalArgumentException("the CBOM sync skip retention must be within 1..%d days, was %d"
                    .formatted(UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS, skipRetentionDays));
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
                defaultIfNull(utils.getCbomSyncSkipRetentionDays(), DEFAULT_SKIP_RETENTION_DAYS));
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
