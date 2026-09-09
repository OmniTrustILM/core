package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.cbom.asset.identity.NormalizedAsset;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What {@link PqcEvaluator#fromStoredRow} recovers from the folded columns that the derivation carried in memory.
 *
 * <p>
 * <b>The fixture is folded, never hand-typed.</b> Writing {@code new CryptoAssetIdentityFields(..., "X-Wing", ...)} by
 * hand would pass while the real thing failed: the column holds {@link CryptoAssetIdentityFields#normalized()}'s
 * output, which lowercases the family, and {@code AssetNormalizer} compares family tokens case-sensitively. A folded
 * {@code x-wing} therefore took the non-hybrid scan path and re-derived different components. Building the fixture
 * through the real fold is what makes these tests able to fail.
 */
class PqcStoredRowTest {

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
    private final PqcEvaluator evaluator = new PqcEvaluator(normalizer);

    /**
     * The components live on {@link NormalizedAsset} alone and have no column, deliberately -- they are out-of-key by
     * construction, and adding a column would be a schema change with an identity fence and a merge election resting on
     * the shipped column set. So the row re-derives them from the folded family and name.
     */
    @Test
    void aHybridsComponentsAreReDerivedFromTheFoldedColumns() {
        JsonNode component = PqcEvaluatorTest.algorithm("X25519-ML-KEM-768");
        NormalizedAsset asset = normalizer.normalize(component).asset();

        PqcRuleInput stored = evaluator.fromStoredRow(storedRow(asset), component.get("cryptoProperties"));

        assertThat(asset.hybridComponents()).isNotEmpty();
        assertThat(stored.hybridComponents()).isEqualTo(asset.hybridComponents());
    }

    /**
     * The type mismatch that would make a size comparison silently false: the derivation carries an {@code Integer} and
     * the column carries text.
     */
    @Test
    void theParameterSetSurvivesTheRoundTripThroughItsTextColumn() {
        NormalizedAsset asset = normalizer.normalize(PqcEvaluatorTest.algorithm("RSA-2048")).asset();
        assertThat(asset.parameterSet()).isEqualTo(2048);
        assertThat(evaluator.fromStoredRow(storedRow(asset), null).parameterSet()).isEqualTo(2048);
    }

    /**
     * Fullwidth digits are not digits to the name grammar, so the derivation of {@code X25519-ML-KEM-７６８} records a
     * component without its size and elects {@code ECDH} where the ASCII spelling elects {@code X-Wing}. The two are
     * different rows; the column is folded before it is read, so the row recovers the size and reaches the ASCII
     * spelling's verdict.
     */
    @Test
    void aFoldChangingNameDecidesAsItsAsciiSpellingDoes() {
        JsonNode fullwidth = PqcEvaluatorTest.algorithm("X25519-ML-KEM-７６８");
        JsonNode ascii = PqcEvaluatorTest.algorithm("X25519-ML-KEM-768");
        NormalizedAsset fullwidthAsset = normalizer.normalize(fullwidth).asset();
        NormalizedAsset asciiAsset = normalizer.normalize(ascii).asset();

        PqcRuleInput stored = evaluator.fromStoredRow(storedRow(fullwidthAsset), fullwidth.get("cryptoProperties"));
        PqcDecision decision = evaluator.evaluate(stored, null);
        PqcDecision asciiDecision = evaluator
                .evaluate(evaluator.fromStoredRow(storedRow(asciiAsset), ascii.get("cryptoProperties")), null);

        assertThat(fullwidthAsset.hybridComponents()).containsExactly("ecdh", "ml-kem");
        assertThat(stored.hybridComponents()).containsExactly("ecdh", "ml-kem-768");
        assertThat(decision.verdict()).isEqualTo(asciiDecision.verdict());
        assertThat(decision.ruleId()).isEqualTo(asciiDecision.ruleId()).isEqualTo("PQC-HYBRID-PQC-STANDARDIZED");
    }

    private static CryptoAssetIdentityFields storedRow(NormalizedAsset asset) {
        return PqcEvaluatorTest.storedRow(asset);
    }
}
