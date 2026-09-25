package com.otilm.core.model.cbom;

import java.util.List;

/**
 * The two counts a cryptographic asset serves side by side. A source contributes one sighting per location it recorded,
 * or one for the report itself when it recorded none, so the pair always reads consistently: an asset never has fewer
 * sightings than sources, and it has sightings exactly when it has sources. The constructor refuses any other pair, so
 * a disagreeing count fails instead of reaching the wire.
 */
public record CryptoAssetCounts(int sourceCount, long sightingCount) {

    public CryptoAssetCounts {
        if (sourceCount < 0 || sightingCount < sourceCount || (sourceCount == 0 && sightingCount != 0)) {
            throw new IllegalStateException("Inconsistent cryptographic asset counts: %d source(s), %d sighting(s)"
                    .formatted(sourceCount, sightingCount));
        }
    }

    /**
     * Sightings one source contributes, given the number of locations it recorded. Mirrored by the {@code CASE} in
     * {@code CryptoAssetRepository#findListRowsByUuids}.
     */
    public static long sightingsOf(int locationCount) {
        if (locationCount < 0) {
            throw new IllegalArgumentException(
                    "A source cannot record a negative number of locations: " + locationCount);
        }
        return Math.max(1, locationCount);
    }

    /** The counts of an asset whose sources recorded the given numbers of locations, one entry per source. */
    public static CryptoAssetCounts ofLocationCounts(List<Integer> locationCountPerSource) {
        long sightingCount = locationCountPerSource.stream().mapToLong(CryptoAssetCounts::sightingsOf).sum();
        return new CryptoAssetCounts(locationCountPerSource.size(), sightingCount);
    }
}
