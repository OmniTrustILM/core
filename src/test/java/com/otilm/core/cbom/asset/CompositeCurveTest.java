package com.otilm.core.cbom.asset;

import java.util.List;
import org.junit.jupiter.api.Test;

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
     * An empty array cannot reach the column -- the normalizer yields null rather than an empty token, and
     * {@code string_to_array} maps SQL NULL to NULL -- so this pins the guard rather than a reachable state. Without it
     * the method would answer the empty string, which is a curve nothing has and every {@code EMPTY} filter would
     * disagree about.
     */
    @Test
    void anEmptyMemberListIsAbsentTooRatherThanTheEmptyString() {
        assertThat(CompositeCurve.join(List.of())).isNull();
    }
}
