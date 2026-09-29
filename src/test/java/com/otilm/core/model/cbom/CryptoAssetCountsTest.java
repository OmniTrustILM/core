package com.otilm.core.model.cbom;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The source count and the occurrence count are served side by side, so they must never contradict each other: no
 * occurrences without a source, no source without an occurrence.
 */
class CryptoAssetCountsTest {

    private static final List<Integer> OCCURRENCE_COUNTS = List.of(0, 1, 2, 55);

    @Test
    void anAssetWithoutSourcesHasNoOccurrences() {
        CryptoAssetCounts counts = CryptoAssetCounts.ofSourceOccurrenceCounts(List.of());

        assertThat(counts.sourceCount()).isZero();
        assertThat(counts.occurrenceCount()).isZero();
    }

    @Test
    void twoSourcesThatRecordedNoLocationAreTwoOccurrences() {
        CryptoAssetCounts counts = CryptoAssetCounts.ofSourceOccurrenceCounts(List.of(0, 0));

        assertThat(counts.sourceCount()).isEqualTo(2);
        assertThat(counts.occurrenceCount())
                .describedAs("each report is an occurrence even without a location")
                .isEqualTo(2);
    }

    @Test
    void aSourceWithLocationsContributesOneOccurrencePerLocation() {
        CryptoAssetCounts counts = CryptoAssetCounts.ofSourceOccurrenceCounts(List.of(0, 0, 2));

        assertThat(counts.sourceCount()).isEqualTo(3);
        assertThat(counts.occurrenceCount()).isEqualTo(4);
    }

    @Test
    void everyCombinationOfSourcesServesAConsistentPair() {
        for (List<Integer> occurrenceCountPerSource : combinationsUpTo(4)) {
            CryptoAssetCounts counts = CryptoAssetCounts.ofSourceOccurrenceCounts(occurrenceCountPerSource);

            assertThat(counts.sourceCount()).isEqualTo(occurrenceCountPerSource.size());
            assertThat(counts.occurrenceCount())
                    .describedAs("occurrences never fall below sources for %s", occurrenceCountPerSource)
                    .isGreaterThanOrEqualTo(counts.sourceCount());
            assertThat(counts.occurrenceCount() == 0)
                    .describedAs("occurrences are zero exactly when sources are zero for %s", occurrenceCountPerSource)
                    .isEqualTo(counts.sourceCount() == 0);
        }
    }

    @ParameterizedTest(name = "{0} source(s) with {1} occurrence(s) is refused")
    @CsvSource({"0, 2", "0, 1", "2, 0", "2, 1", "-1, 0"})
    void aContradictoryPairIsRefused(int sourceCount, long occurrenceCount) {
        assertThatThrownBy(() -> new CryptoAssetCounts(sourceCount, occurrenceCount))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Inconsistent cryptographic asset counts");
    }

    @ParameterizedTest(name = "{0} source(s) with {1} occurrence(s) is accepted")
    @CsvSource({"0, 0", "1, 1", "2, 2", "2, 5"})
    void aConsistentPairIsAccepted(int sourceCount, long occurrenceCount) {
        CryptoAssetCounts counts = new CryptoAssetCounts(sourceCount, occurrenceCount);

        assertThat(counts.sourceCount()).isEqualTo(sourceCount);
        assertThat(counts.occurrenceCount()).isEqualTo(occurrenceCount);
    }

    @Test
    void aNegativeRecordedCountIsRefused() {
        assertThatThrownBy(() -> CryptoAssetCounts.occurrencesOf(-1)).isInstanceOf(IllegalArgumentException.class);
    }

    private static List<List<Integer>> combinationsUpTo(int maxSources) {
        List<List<Integer>> all = new ArrayList<>();
        all.add(List.of());
        List<List<Integer>> previousLength = List.of(List.of());
        for (int length = 1; length <= maxSources; length++) {
            List<List<Integer>> currentLength = new ArrayList<>();
            for (List<Integer> prefix : previousLength) {
                for (Integer recordedCount : OCCURRENCE_COUNTS) {
                    List<Integer> extended = new ArrayList<>(prefix);
                    extended.add(recordedCount);
                    currentLength.add(List.copyOf(extended));
                }
            }
            all.addAll(currentLength);
            previousLength = currentLength;
        }
        return all;
    }
}
