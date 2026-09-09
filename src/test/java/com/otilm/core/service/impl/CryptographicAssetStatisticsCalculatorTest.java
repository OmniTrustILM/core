package com.otilm.core.service.impl;

import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CryptographicAssetStatisticsCalculatorTest {

    @Test
    void densifiesEveryEnumCodeWithZero() {
        CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                .assemble(3, Map.of("algorithm", 3L), Map.of(), Map.of(), 10, 0, Map.of(), null);
        assertEquals(Map
                .of("algorithm", 3L, "certificate", 0L, "protocol", 0L, "related-crypto-material", 0L, "unroutable",
                        0L),
                dto.getStatByType());
        assertEquals(Map.of("ready", 0L, "notReady", 0L, "notApplicable", 0L, "unknown", 0L),
                dto.getStatByPqcVerdict());
        assertEquals(Map.of("pending", 0L, "inProgress", 0L, "synced", 0L, "failed", 0L),
                dto.getSyncCompleteness().getCbomStatBySyncState());
    }

    @Test
    void foldsTheUnassignedVerdictBucketIntoUnknown() {
        // countGroupedUsingSecurityFilter maps a NULL pqc_verdict group key to "Unassigned"; a never-evaluated
        // asset is served as unknown everywhere else, so the fold keeps statistics reconciled with the list
        CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                .assemble(5, Map.of(), Map.of("Unassigned", 3L, "unknown", 1L, "ready", 1L), Map.of(), 10, 0, Map.of(),
                        null);
        assertEquals(4L, dto.getStatByPqcVerdict().get("unknown"));
        assertEquals(1L, dto.getStatByPqcVerdict().get("ready"));
    }

    @Test
    void familyTopNKeepsHighestCountsAndReportsOverflowAndUnassigned() {
        Map<String, Long> families = new HashMap<>();
        for (int i = 1; i <= 12; i++) {
            families.put("family-" + String.format("%02d", i), (long) i);
        }
        families.put("Unassigned", 99L);
        CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                .assemble(0, Map.of(), Map.of(), families, 10, 0, Map.of(), null);
        assertEquals(10, dto.getStatByAlgorithmFamily().size());
        assertFalse(dto.getStatByAlgorithmFamily().containsKey("Unassigned"));
        assertFalse(dto.getStatByAlgorithmFamily().containsKey("family-01")); // the two smallest overflow
        assertFalse(dto.getStatByAlgorithmFamily().containsKey("family-02"));
        assertEquals(List.of("family-12", "family-11"),
                dto.getStatByAlgorithmFamily().keySet().stream().limit(2).toList());
        assertEquals(12L, dto.getDistinctAlgorithmFamilyCount());
        assertEquals(99L, dto.getUnassignedAssetCount());
    }

    @Test
    void familyTiesBreakOnKeyForDeterminism() {
        // two families with equal counts → ascending key order between them
        Map<String, Long> families = Map.of("zebra", 5L, "apple", 5L, "banana", 3L);
        CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                .assemble(0, Map.of(), Map.of(), families, 10, 0, Map.of(), null);
        assertEquals(3, dto.getStatByAlgorithmFamily().size());
        assertEquals(List.of("apple", "zebra", "banana"), dto.getStatByAlgorithmFamily().keySet().stream().toList());
    }

    @Test
    void badgesAndTimestampPassThrough() {
        OffsetDateTime syncedAt = OffsetDateTime.parse("2026-08-30T12:00:00Z");
        CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                .assemble(7, Map.of(), Map.of(), Map.of(), 10, 4, Map.of("synced", 4L), syncedAt);
        assertEquals(7L, dto.getTotalAssets());
        assertEquals(4L, dto.getSourceCbomCount());
        assertEquals(syncedAt, dto.getSyncCompleteness().getLastCompletedSyncAt());
        assertNull(CryptographicAssetStatisticsCalculator
                .assemble(0, Map.of(), Map.of(), Map.of(), 10, 0, Map.of(), null)
                .getSyncCompleteness()
                .getLastCompletedSyncAt());
    }

    /**
     * F4: a key dense() has no declared code for is not a bucket it can silently drop -- a discarded bucket is a chart
     * that lies.
     */
    @Test
    void anUnmappedTypeKeyThrows() {
        assertThrows(IllegalStateException.class, () -> CryptographicAssetStatisticsCalculator
                .assemble(1, Map.of("bogus-type", 1L), Map.of(), Map.of(), 10, 0, Map.of(), null));
    }

    /**
     * F4: statByType folds nothing (asset_type is NOT NULL, so densifying it never names a foldNullInto target). An
     * Unassigned bucket appearing there means the invariant that every stored type is a real enum code broke, and that
     * must fail loud rather than serve a silently-zeroed extra bucket.
     */
    @Test
    void theUnassignedSentinelWithNoFoldTargetThrowsForType() {
        assertThrows(IllegalStateException.class,
                () -> CryptographicAssetStatisticsCalculator
                        .assemble(1, Map.of(CryptographicAssetStatisticsCalculator.UNASSIGNED_KEY, 1L), Map.of(),
                                Map.of(), 10, 0, Map.of(), null));
    }

    /** F4: the same rule for cbomStatBySyncState -- asset_sync_state is NOT NULL too. */
    @Test
    void theUnassignedSentinelWithNoFoldTargetThrowsForSyncState() {
        assertThrows(IllegalStateException.class,
                () -> CryptographicAssetStatisticsCalculator
                        .assemble(0, Map.of(), Map.of(), Map.of(), 10, 0,
                                Map.of(CryptographicAssetStatisticsCalculator.UNASSIGNED_KEY, 1L), null));
    }

    @Test
    void fewerFamiliesThanTheLimitAreAllServed() {
        // 3 families, limit 10 → all 3 present, distinct == 3
        Map<String, Long> families = Map.of("family-a", 2L, "family-b", 5L, "family-c", 1L);
        CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                .assemble(0, Map.of(), Map.of(), families, 10, 0, Map.of(), null);
        assertEquals(3, dto.getStatByAlgorithmFamily().size());
        assertEquals(3L, dto.getDistinctAlgorithmFamilyCount());
        assertEquals(List.of("family-b", "family-a", "family-c"),
                dto.getStatByAlgorithmFamily().keySet().stream().toList());
    }
}
