package com.otilm.core.service.impl;

import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod.Bucket;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SigningRecordStatisticsCalculatorTest {

    @Test
    void flattenScheme_delegatedIgnoresManagedType() {
        assertThat(SigningRecordStatisticsCalculator.flattenScheme(SigningScheme.DELEGATED, null)).isEqualTo("delegated");
        assertThat(SigningRecordStatisticsCalculator.flattenScheme(SigningScheme.DELEGATED, ManagedSigningType.STATIC_KEY))
                .isEqualTo("delegated");
    }

    @Test
    void flattenScheme_managedCombinesWithManagedType() {
        assertThat(SigningRecordStatisticsCalculator.flattenScheme(SigningScheme.MANAGED, ManagedSigningType.STATIC_KEY))
                .isEqualTo("managed_static_key");
        assertThat(SigningRecordStatisticsCalculator.flattenScheme(SigningScheme.MANAGED, ManagedSigningType.ONE_TIME_KEY))
                .isEqualTo("managed_one_time_key");
    }

    @Test
    void flattenScheme_managedWithoutTypeFallsBackToSchemeCode() {
        assertThat(SigningRecordStatisticsCalculator.flattenScheme(SigningScheme.MANAGED, null)).isEqualTo("managed");
    }

    @Test
    void topRequesters_keepsHighestCountsInDescendingOrder() {
        Map<String, Long> all = new LinkedHashMap<>();
        all.put("alice", 2L);
        all.put("bob", 9L);
        all.put("carol", 5L);

        Map<String, Long> top = SigningRecordStatisticsCalculator.topRequesters(all, 2);

        assertThat(top.keySet()).containsExactly("bob", "carol");
        assertThat(top).containsEntry("bob", 9L).containsEntry("carol", 5L);
    }

    @Test
    void topRequesters_returnsAllWhenFewerThanLimit() {
        Map<String, Long> all = Map.of("alice", 1L, "bob", 2L);

        assertThat(SigningRecordStatisticsCalculator.topRequesters(all, 10)).hasSize(2);
    }

    @Test
    void denseBuckets_dailyFillsEmptyBucketsWithZeroInOrder() {
        Instant from = Instant.parse("2026-06-09T08:30:00Z");
        Instant to = Instant.parse("2026-06-11T10:00:00Z");
        Map<String, Long> sparse = Map.of("2026-06-10T00:00:00Z", 4L);

        Map<String, Long> dense = SigningRecordStatisticsCalculator.denseBuckets(from, to, Bucket.DAY, sparse);

        assertThat(dense.keySet()).containsExactly(
                "2026-06-09T00:00:00Z", "2026-06-10T00:00:00Z", "2026-06-11T00:00:00Z");
        assertThat(List.copyOf(dense.values())).containsExactly(0L, 4L, 0L);
    }

    @Test
    void denseBuckets_hourlyBucketsKeyByHour() {
        Instant from = Instant.parse("2026-06-11T08:15:00Z");
        Instant to = Instant.parse("2026-06-11T10:05:00Z");
        Map<String, Long> sparse = Map.of("2026-06-11T09:00:00Z", 7L);

        Map<String, Long> dense = SigningRecordStatisticsCalculator.denseBuckets(from, to, Bucket.HOUR, sparse);

        assertThat(dense.keySet()).containsExactly(
                "2026-06-11T08:00:00Z", "2026-06-11T09:00:00Z", "2026-06-11T10:00:00Z");
        assertThat(dense).containsEntry("2026-06-11T09:00:00Z", 7L);
    }
}
