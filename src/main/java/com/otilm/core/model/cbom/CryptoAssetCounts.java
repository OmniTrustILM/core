package com.otilm.core.model.cbom;

import java.util.List;

/**
 * The two counts a cryptographic asset serves side by side. A source contributes one occurrence per evidence entry it
 * recorded, or one for the report itself when it recorded none, so the pair always reads consistently: an asset never
 * has fewer occurrences than sources, and it has occurrences exactly when it has sources. The constructor refuses any
 * other pair, so a disagreeing count fails instead of reaching the wire.
 */
public record CryptoAssetCounts(int sourceCount, long occurrenceCount) {

    public CryptoAssetCounts {
        if (sourceCount < 0 || occurrenceCount < sourceCount || (sourceCount == 0 && occurrenceCount != 0)) {
            throw new IllegalStateException("Inconsistent cryptographic asset counts: %d source(s), %d occurrence(s)"
                    .formatted(sourceCount, occurrenceCount));
        }
    }

    /**
     * Occurrences one source contributes, given the number of evidence entries it recorded. Mirrored by the
     * {@code CASE} in {@code CryptoAssetRepository#findListRowsByUuids}.
     */
    public static long occurrencesOf(int recordedCount) {
        if (recordedCount < 0) {
            throw new IllegalArgumentException(
                    "A source cannot record a negative number of evidence entries: " + recordedCount);
        }
        return Math.max(1, recordedCount);
    }

    /** The counts of an asset whose sources recorded the given numbers of evidence entries, one entry per source. */
    public static CryptoAssetCounts ofSourceOccurrenceCounts(List<Integer> occurrenceCountPerSource) {
        long occurrenceCount = occurrenceCountPerSource.stream().mapToLong(CryptoAssetCounts::occurrencesOf).sum();
        return new CryptoAssetCounts(occurrenceCountPerSource.size(), occurrenceCount);
    }
}
