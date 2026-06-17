package com.otilm.core.service.impl;

import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod.Bucket;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure transformations behind the Signing Record statistics, kept free of Spring and persistence so they can be
 * unit-tested directly. The SQL aggregation lives in the service; this class only reshapes its results.
 */
final class SigningRecordStatisticsCalculator {

    /** ISO-8601 UTC instant, e.g. {@code 2026-06-11T14:00:00Z}. Must match the Postgres {@code to_char} format used to bucket. */
    private static final DateTimeFormatter BUCKET_KEY_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private SigningRecordStatisticsCalculator() {
    }

    /**
     * Flattens the signing scheme and managed signing type into a single dashboard value:
     * {@code delegated}, {@code managed_static_key}, {@code managed_one_time_key} (and more later).
     */
    static String flattenScheme(SigningScheme scheme, ManagedSigningType managedType) {
        if (scheme != SigningScheme.MANAGED) {
            return scheme.getCode();
        }
        return managedType == null ? scheme.getCode() : scheme.getCode() + "_" + managedType.getCode();
    }

    /** Keeps the {@code limit} highest counts, descending by count and then by key for stable ordering. */
    static Map<String, Long> topRequesters(Map<String, Long> all, int limit) {
        return all.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), LinkedHashMap::putAll);
    }

    /**
     * Expands a sparse bucket→count map into a dense, ordered series covering every bucket from {@code fromInclusive}
     * to {@code toInclusive}, filling gaps with zero. Sparse keys must already be formatted by {@link #bucketKey}.
     */
    static Map<String, Long> denseBuckets(Instant fromInclusive, Instant toInclusive, Bucket bucket, Map<String, Long> sparse) {
        Duration step = bucket == Bucket.HOUR ? Duration.ofHours(1) : Duration.ofDays(1);
        Map<String, Long> dense = new LinkedHashMap<>();
        Instant cursor = truncate(fromInclusive, bucket);
        while (!cursor.isAfter(toInclusive)) {
            String key = bucketKey(cursor, bucket);
            dense.put(key, sparse.getOrDefault(key, 0L));
            cursor = cursor.plus(step);
        }
        return dense;
    }

    /** Formats an instant as the canonical UTC bucket key after truncating it to the bucket granularity. */
    static String bucketKey(Instant instant, Bucket bucket) {
        return BUCKET_KEY_FORMAT.format(truncate(instant, bucket));
    }

    private static Instant truncate(Instant instant, Bucket bucket) {
        return instant.truncatedTo(bucket == Bucket.HOUR ? ChronoUnit.HOURS : ChronoUnit.DAYS);
    }
}
