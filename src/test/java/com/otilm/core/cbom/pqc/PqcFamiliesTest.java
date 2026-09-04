package com.otilm.core.cbom.pqc;

import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The completeness gate on the disposition table.
 *
 * <p>
 * The acceptance criteria say ruling (a) is not discharged by a prose sentence but by a table plus a test that asserts
 * each row, so no family silently reaches {@code unknown} by omission. This is that test. It is also what a generated
 * {@code pqcFamilies} table would have given for free, and is therefore the standing cost of core#2196's ruling C12
 * being carried rather than implemented.
 */
class PqcFamiliesTest {

    private final IdentityTables tables = IdentityTables.load();

    @Test
    void everyRatifiedFamilyHasADisposition() {
        Set<String> ratified = new TreeSet<>(tables.families());
        ratified.addAll(tables.pseudoFamilies().keySet());

        Set<String> undispositioned = new TreeSet<>(ratified);
        undispositioned.removeIf(family -> PqcFamilies.of(family) != null);

        assertThat(undispositioned)
                .describedAs("every family the identity tables ratify must have a readiness disposition, or an asset "
                        + "carrying it reaches `unknown` because nobody classified it rather than because the rules "
                        + "cannot tell")
                .isEmpty();
    }

    @Test
    void noDispositionNamesAFamilyTheTablesDoNot() {
        Set<String> ratified = new TreeSet<>(tables.families());
        ratified.addAll(tables.pseudoFamilies().keySet());

        Set<String> unknownToTheTables = new TreeSet<>(PqcFamilies.dispositions().keySet());
        unknownToTheTables.removeAll(ratified);

        assertThat(unknownToTheTables)
                .describedAs("a disposition for a family no table names is dead weight, and usually a spelling that "
                        + "drifted from the ratified one -- which is the drift ruling C12 exists to end")
                .isEmpty();
    }

    /**
     * The pseudo-families are the whole reason this table cannot be derived from the registry: the upstream CycloneDX
     * cryptography-defs registry names no pre-standard candidate at all.
     */
    @Test
    void everyPseudoFamilyIsDispositioned() {
        assertThat(tables.pseudoFamilies().keySet())
                .allSatisfy(pseudo -> assertThat(PqcFamilies.of(pseudo))
                        .describedAs("pseudo-family %s", pseudo)
                        .isNotNull());
    }

    @Test
    void theBrokenCandidatesAreSeparatedFromTheMerelySuperseded() {
        assertThat(PqcFamilies.of("SIKE")).isEqualTo(FamilyClass.PQC_BROKEN);
        assertThat(PqcFamilies.of("Rainbow")).isEqualTo(FamilyClass.PQC_BROKEN);
        assertThat(PqcFamilies.of("Kyber")).isEqualTo(FamilyClass.PQC_PRESTANDARD);
        assertThat(PqcFamilies.of("Dilithium")).isEqualTo(FamilyClass.PQC_PRESTANDARD);
        assertThat(PqcFamilies.of("SPHINCS+")).isEqualTo(FamilyClass.PQC_PRESTANDARD);
    }

    /**
     * The three standardised schemes and the two stateful hash-based signature schemes are the only families that may
     * answer `ready` on post-quantum grounds.
     */
    @Test
    void onlyTheStandardisedSchemesAreReadyOnPostQuantumGrounds() {
        Set<String> standardized = new TreeSet<>();
        PqcFamilies.dispositions().forEach((family, disposition) -> {
            if (disposition == FamilyClass.PQC_STANDARDIZED) {
                standardized.add(family);
            }
        });
        assertThat(standardized).containsExactlyInAnyOrder("ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS");
    }

    /**
     * {@code bcrypt} sits in {@code pseudoFamilies} beside the post-quantum candidates and is a password hash. The
     * ticket's "30 pre-standard PQC families" counts it as one of them, and this pins that it is not treated as one.
     */
    @Test
    void bcryptIsAPasswordHashRatherThanAPqcCandidate() {
        assertThat(tables.pseudoFamilies()).containsKey("bcrypt");
        assertThat(PqcFamilies.of("bcrypt")).isEqualTo(FamilyClass.QUANTUM_RESISTANT_SYMMETRIC);
    }

    /** FN-DSA is the standardised name for Falcon and appears in no ratified table under any spelling. */
    @Test
    void fnDsaIsInNoRatifiedTable() {
        assertThat(tables.familyToken("FN-DSA"))
                .describedAs("if this resolves, the tables gained FN-DSA and the FAMILY-UNRESOLVED gap has closed")
                .isNull();
    }
}
