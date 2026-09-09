package com.otilm.core.service.impl;

import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import com.otilm.api.model.client.dashboard.CryptographicAssetSyncCompletenessDto;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure transformations behind the cryptographic asset statistics, kept free of Spring and persistence so they can be
 * unit-tested directly. The SQL aggregation lives in the service; this class only reshapes its results.
 */
final class CryptographicAssetStatisticsCalculator {

    /**
     * The literal {@code SecurityFilterRepositoryImpl.countGroupedUsingSecurityFilter} substitutes for a NULL group
     * key. For verdicts it means "never evaluated" and folds into {@code unknown}; for families it is the contract's
     * unassignedAssetCount and never occupies a top-N slot.
     *
     * <p>
     * The literal is duplicated from {@code SecurityFilterRepositoryImpl}'s NULL group-key substitution, not shared
     * with it. Collision with a genuine stored family is prevented by {@code CryptoAssetIdentityFields#fold()}
     * lowercasing producer text before storage, so a stored "unassigned" coexists with this sentinel while a stored
     * "Unassigned" can never occur.
     */
    static final String UNASSIGNED_KEY = "Unassigned";

    private CryptographicAssetStatisticsCalculator() {
    }

    static CryptographicAssetStatisticsDto assemble(long totalAssets, Map<String, Long> byType,
            Map<String, Long> byVerdict, Map<String, Long> byFamily, int topFamilies, long sourceCbomCount,
            Map<String, Long> cbomBySyncState, OffsetDateTime lastCompletedSyncAt) {
        CryptographicAssetStatisticsDto dto = new CryptographicAssetStatisticsDto();
        dto.setTotalAssets(totalAssets);
        dto.setSourceCbomCount(sourceCbomCount);
        dto.setStatByType(dense(byType, typeCodes(), null));
        dto.setStatByPqcVerdict(dense(byVerdict, verdictCodes(), PqcVerdict.UNKNOWN.getCode()));
        Map<String, Long> families = new HashMap<>(byFamily);
        Long unassigned = families.remove(UNASSIGNED_KEY);
        dto.setUnassignedAssetCount(unassigned == null ? 0L : unassigned);
        dto.setDistinctAlgorithmFamilyCount((long) families.size());
        dto.setStatByAlgorithmFamily(top(families, topFamilies));
        CryptographicAssetSyncCompletenessDto completeness = new CryptographicAssetSyncCompletenessDto();
        completeness.setCbomStatBySyncState(dense(cbomBySyncState, syncStateCodes(), null));
        completeness.setLastCompletedSyncAt(lastCompletedSyncAt);
        dto.setSyncCompleteness(completeness);
        return dto;
    }

    /**
     * Every code present with 0 when none, in enum declaration order; a NULL bucket folds into {@code foldNullInto}
     * when one is given. Any other key -- one {@code codes} does not list, or the sentinel when nothing folds it -- is
     * not a bucket this dense map has room for, and is not dropped silently: a discarded bucket is a chart that
     * silently lies, so it fails the request instead.
     */
    private static Map<String, Long> dense(Map<String, Long> sparse, List<String> codes, String foldNullInto) {
        Map<String, Long> result = new LinkedHashMap<>();
        for (String code : codes) {
            result.put(code, sparse.getOrDefault(code, 0L));
        }
        for (Map.Entry<String, Long> entry : sparse.entrySet()) {
            String key = entry.getKey();
            if (codes.contains(key)) {
                continue;
            }
            if (key.equals(UNASSIGNED_KEY) && foldNullInto != null) {
                result.merge(foldNullInto, entry.getValue(), Long::sum);
                continue;
            }
            throw new IllegalStateException("Unmapped statistics group key \"%s\": expected one of %s%s"
                    .formatted(key, codes,
                            foldNullInto != null ? " or the \"%s\" sentinel".formatted(UNASSIGNED_KEY) : ""));
        }
        return result;
    }

    /** Highest counts first, count ties broken on ascending key so pagination of the chart is stable. */
    private static Map<String, Long> top(Map<String, Long> all, int limit) {
        return all
                .entrySet()
                .stream()
                .sorted(Map.Entry
                        .<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), LinkedHashMap::putAll);
    }

    private static List<String> typeCodes() {
        return Arrays.stream(CryptographicAssetType.values()).map(CryptographicAssetType::getCode).toList();
    }

    private static List<String> verdictCodes() {
        return Arrays.stream(PqcVerdict.values()).map(PqcVerdict::getCode).toList();
    }

    private static List<String> syncStateCodes() {
        return Arrays.stream(CbomAssetSyncState.values()).map(CbomAssetSyncState::getCode).toList();
    }
}
