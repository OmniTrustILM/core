package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.util.Map;
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
        assertThat(familiesIn(FamilyClass.PQC_STANDARDIZED))
                .containsExactlyInAnyOrder("ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS");
    }

    /**
     * The ready column, pinned by size, and the one other class that answers {@code ready} on post-quantum grounds,
     * pinned by membership. Moving a pre-standard scheme into either used to leave the whole suite green; now the move
     * has to be declared here in the same commit.
     */
    @Test
    void aMoveIntoTheReadyColumnMustBeDeclared() {
        assertThat(familiesIn(FamilyClass.PQC_HYBRID)).containsExactly("X-Wing");

        Set<String> ready = new TreeSet<>();
        PqcFamilies.dispositions().forEach((family, disposition) -> {
            if (disposition.verdict() == PqcVerdict.READY) {
                ready.add(family);
            }
        });
        assertThat(ready).hasSize(55);
    }

    private static Set<String> familiesIn(FamilyClass disposition) {
        Set<String> families = new TreeSet<>();
        PqcFamilies.dispositions().forEach((family, candidate) -> {
            if (candidate == disposition) {
                families.add(family);
            }
        });
        return families;
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

    /**
     * Cross-checks the hand classification against the artifact's own {@code primitiveDefaults}.
     *
     * <p>
     * The disposition itself cannot come from the tables -- they file RSA and ML-DSA alike as {@code signature}, MD5
     * and SHA-3 alike as {@code hash} -- but five primitives do map onto exactly one class, and those the artifact can
     * police. It covers 27 of the 130 families, and its value is for the ones added later: a post-quantum KEM filed as
     * classical, or a key-agreement scheme filed as symmetric, now fails the build instead of being caught by whoever
     * next reads the table.
     *
     * <p>
     * Note what it does <em>not</em> catch. The misclassifications an adversarial review actually found -- GeMSS, IDEA,
     * Yarrow, RIPEMD -- all sit under {@code signature}, {@code block-cipher} and {@code hash}, the primitives that
     * legitimately span several classes. There is no substitute for reading the table.
     */
    @Test
    void theArtifactsOwnPrimitivesAgreeWithTheDispositions() {
        Map<String, Set<FamilyClass>> permitted = Map
                .of("key-agree", Set.of(FamilyClass.SHOR_BREAKABLE), "pke", Set.of(FamilyClass.SHOR_BREAKABLE), "ae",
                        Set.of(FamilyClass.QUANTUM_RESISTANT_SYMMETRIC), "mac",
                        Set.of(FamilyClass.QUANTUM_RESISTANT_SYMMETRIC), "kem",
                        Set
                                .of(FamilyClass.PQC_STANDARDIZED, FamilyClass.PQC_PRESTANDARD, FamilyClass.PQC_BROKEN,
                                        FamilyClass.PQC_HYBRID));

        assertThat(tables.primitiveDefaults()).isNotEmpty();
        tables.primitiveDefaults().forEach((family, primitive) -> {
            Set<FamilyClass> allowed = permitted.get(primitive);
            if (allowed != null) {
                assertThat(PqcFamilies.of(family))
                        .describedAs("%s is a %s in the ratified tables", family, primitive)
                        .isIn(allowed);
            }
        });
    }

    /**
     * Pins the identity tables this rule set was authored against.
     *
     * <p>
     * Nothing else couples the two. The carried rulings move verdicts without touching a line of this package -- C8
     * alone turns {@code RC4-MD5} from a {@code CLASSICAL-LEGACY} family into a suite name, and C12 would replace this
     * whole table -- so a regenerated artifact must force someone to decide whether {@link PqcRuleset#VERSION} bumps
     * and the sweep re-runs. Failing here is not a defect: re-read the dispositions against the new tables, bump the
     * rule-set version if any verdict moved, and update this digest in the same commit.
     */
    @Test
    void theRuleSetIsPinnedToTheTablesItWasAuthoredAgainst() throws Exception {
        byte[] artifact;
        try (var in = IdentityTables.class.getClassLoader().getResourceAsStream("cbom/identity-tables.json")) {
            artifact = in.readAllBytes();
        }
        String digest = java.util.HexFormat
                .of()
                .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(artifact));

        assertThat(digest).isEqualTo("474e3dc95c5e155f9dea80ee0f1620081f8170e20a9dc9f29e1e2ac09337e1d1");
    }

    /** FN-DSA is the standardised name for Falcon and appears in no ratified table under any spelling. */
    @Test
    void fnDsaIsInNoRatifiedTable() {
        assertThat(tables.familyToken("FN-DSA"))
                .describedAs("if this resolves, the tables gained FN-DSA and the FAMILY-UNRESOLVED gap has closed")
                .isNull();
    }
}
