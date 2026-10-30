package com.otilm.core.cbom.asset;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The inverse of the storage split, which is what keeps the identity spelling reachable from an array column.
 *
 * <p>
 * The column holds a curve's members; the identity preimage, the PQC rules and the API contract all read the
 * {@code +}-joined composite the normalizer produced. Every one of those breaks quietly if the join stops reproducing
 * that spelling, and none of them would say so -- a wrong spelling is still a valid string.
 */
class CompositeCurveTest {

    @Test
    void aSingleCurveJoinsBackToItself() {
        assertThat(CompositeCurve.join(List.of("secp256r1"))).isEqualTo("secp256r1");
    }

    /**
     * The order is the normalizer's, which sorted and deduplicated the members before joining them; the split preserved
     * it, so the join reproduces the preimage byte for byte rather than merely a permutation of it.
     */
    @Test
    void aHybridJoinsBackInTheOrderItsMembersAreStoredIn() {
        assertThat(CompositeCurve.join(List.of("other/curve25519", "other/curve448")))
                .isEqualTo("other/curve25519+other/curve448");
    }

    @Test
    void anAbsentCurveStaysAbsentRatherThanBecomingEmptyText() {
        assertThat(CompositeCurve.join(null)).isNull();
    }

    /**
     * An empty array cannot reach the column -- the normalizer yields null rather than an empty token, and the split
     * maps a blank composite to null -- so this pins the guard rather than a reachable state. Without it the method
     * would answer the empty string, which is a curve nothing has and every {@code EMPTY} filter would disagree about.
     */
    @Test
    void anEmptyMemberListIsAbsentTooRatherThanTheEmptyString() {
        assertThat(CompositeCurve.join(List.of())).isNull();
    }

    @Test
    void aSingleCurveSplitsToItsOwnSoleMember() {
        assertThat(CompositeCurve.split("secp256r1")).containsExactly("secp256r1");
    }

    @Test
    void aCompositeSplitsIntoItsMembersInTheOrderItSpelledThem() {
        assertThat(CompositeCurve.split("other/curve25519+other/curve448"))
                .containsExactly("other/curve25519", "other/curve448");
    }

    /**
     * The invariant every other caller rests on: the storage projection is lossless, so the preimage spelling survives
     * a round trip through the column and the API reports back what the normalizer produced.
     */
    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "other/curve25519+other/curve448", "brainpoolP256r1+secp256r1+secp384r1"})
    void joiningWhatWasSplitReproducesTheSpelling(String composite) {
        assertThat(CompositeCurve.join(CompositeCurve.split(composite))).isEqualTo(composite);
    }

    /**
     * A blank composite is absent, not a one-element array holding the empty string. That array would report
     * {@code null} back through {@link CompositeCurve#join} and {@code ""} to anything reading the column joined, so
     * one row would answer two different things about the same curve.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void anAbsentOrBlankCompositeSplitsToNothingRatherThanToAnEmptyMember(String composite) {
        assertThat(CompositeCurve.split(composite)).isNull();
    }
}
