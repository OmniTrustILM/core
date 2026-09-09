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
 * These are deployment-time protocol parameters, not operator settings: the page size is bounded by the repository's
 * contract, and the overlap has to cover clock skew between Core and the object store plus the longest upload the
 * deployment expects (S3 stamps a multipart upload with its initiation time). The repository documents 60 s.
 *
 * @param pageSize the {@code limit} sent with {@code GET /api/v1/bom}; 1..1000 per the contract, 1000 by default
 * @param overlap how far behind the last successful run's start the next run lists from; 60 s by default. A bare number
 * binds as seconds: without {@code @DurationUnit} Spring reads it as milliseconds, so {@code 60} would silently mean 60
 * ms and the overlap would vanish
 * @param skippedRetryRuns how many later runs retry an entry that could not be stored before it is recorded as
 * permanently skipped; 3 by default, 0 writes an entry off at its first failure
 */
@ConfigurationProperties(prefix = "cbom.sync")
public record CbomSyncProperties(@DefaultValue("1000") int pageSize,
        @DefaultValue("60s") @DurationUnit(ChronoUnit.SECONDS) Duration overlap,
        @DefaultValue("3") int skippedRetryRuns) {

    public static final int MIN_PAGE_SIZE = 1;
    public static final int MAX_PAGE_SIZE = 1000;

    public CbomSyncProperties {
        if (pageSize < MIN_PAGE_SIZE || pageSize > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("cbom.sync.page-size must be within %d..%d, was %d"
                    .formatted(MIN_PAGE_SIZE, MAX_PAGE_SIZE, pageSize));
        }
        if (overlap == null || overlap.isNegative()) {
            throw new IllegalArgumentException("cbom.sync.overlap must be a non-negative duration, was " + overlap);
        }
        if (skippedRetryRuns < 0) {
            throw new IllegalArgumentException(
                    "cbom.sync.skipped-retry-runs must be zero or positive, was " + skippedRetryRuns);
        }
    }

    /** The first failed attempt plus the configured retries: the attempt count at which an entry is written off. */
    public int maxAttempts() {
        return 1 + skippedRetryRuns;
    }
}
