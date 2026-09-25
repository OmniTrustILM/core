package com.otilm.core.model.cbom;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The source count and the sighting count are served side by side, so they must never contradict each other: no
 * sightings without a source, no source without a sighting.
 */
class CryptoAssetCountsTest {

    private static final List<Integer> LOCATION_COUNTS = List.of(0, 1, 2, 55);

    @Test
    void anAssetWithoutSourcesHasNoSightings() {
        CryptoAssetCounts counts = CryptoAssetCounts.ofLocationCounts(List.of());

        assertThat(counts.sourceCount()).isZero();
        assertThat(counts.sightingCount()).isZero();
    }

    @Test
    void twoSourcesThatRecordedNoLocationAreTwoSightings() {
        CryptoAssetCounts counts = CryptoAssetCounts.ofLocationCounts(List.of(0, 0));

        assertThat(counts.sourceCount()).isEqualTo(2);
        assertThat(counts.sightingCount())
                .describedAs("each report is a sighting even without a location")
                .isEqualTo(2);
    }

    @Test
    void aSourceWithLocationsContributesOneSightingPerLocation() {
        CryptoAssetCounts counts = CryptoAssetCounts.ofLocationCounts(List.of(0, 0, 2));

        assertThat(counts.sourceCount()).isEqualTo(3);
        assertThat(counts.sightingCount()).isEqualTo(4);
    }

    @Test
    void everyCombinationOfSourcesServesAConsistentPair() {
        for (List<Integer> locationCountPerSource : combinationsUpTo(4)) {
            CryptoAssetCounts counts = CryptoAssetCounts.ofLocationCounts(locationCountPerSource);

            assertThat(counts.sourceCount()).isEqualTo(locationCountPerSource.size());
            assertThat(counts.sightingCount())
                    .describedAs("sightings never fall below sources for %s", locationCountPerSource)
                    .isGreaterThanOrEqualTo(counts.sourceCount());
            assertThat(counts.sightingCount() == 0)
                    .describedAs("sightings are zero exactly when sources are zero for %s", locationCountPerSource)
                    .isEqualTo(counts.sourceCount() == 0);
        }
    }

    @ParameterizedTest(name = "{0} source(s) with {1} sighting(s) is refused")
    @CsvSource({"0, 2", "0, 1", "2, 0", "2, 1", "-1, 0"})
    void aContradictoryPairIsRefused(int sourceCount, long sightingCount) {
        assertThatThrownBy(() -> new CryptoAssetCounts(sourceCount, sightingCount))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Inconsistent cryptographic asset counts");
    }

    @ParameterizedTest(name = "{0} source(s) with {1} sighting(s) is accepted")
    @CsvSource({"0, 0", "1, 1", "2, 2", "2, 5"})
    void aConsistentPairIsAccepted(int sourceCount, long sightingCount) {
        CryptoAssetCounts counts = new CryptoAssetCounts(sourceCount, sightingCount);

        assertThat(counts.sourceCount()).isEqualTo(sourceCount);
        assertThat(counts.sightingCount()).isEqualTo(sightingCount);
    }

    @Test
    void aNegativeLocationCountIsRefused() {
        assertThatThrownBy(() -> CryptoAssetCounts.sightingsOf(-1)).isInstanceOf(IllegalArgumentException.class);
    }

    private static List<List<Integer>> combinationsUpTo(int maxSources) {
        List<List<Integer>> all = new ArrayList<>();
        all.add(List.of());
        List<List<Integer>> previousLength = List.of(List.of());
        for (int length = 1; length <= maxSources; length++) {
            List<List<Integer>> currentLength = new ArrayList<>();
            for (List<Integer> prefix : previousLength) {
                for (Integer locationCount : LOCATION_COUNTS) {
                    List<Integer> extended = new ArrayList<>(prefix);
                    extended.add(locationCount);
                    currentLength.add(List.copyOf(extended));
                }
            }
            all.addAll(currentLength);
            previousLength = currentLength;
        }
        return all;
    }
}
