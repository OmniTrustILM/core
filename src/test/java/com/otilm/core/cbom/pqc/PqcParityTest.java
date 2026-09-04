package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.cbom.asset.identity.NormalizedAsset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The evaluator's two callers must reach the same answer.
 *
 * <p>
 * Ingest (core#2073) evaluates in memory from a {@link NormalizedAsset}; the re-evaluation sweep evaluates from a
 * stored row -- the ten folded identity columns plus one elected source's payload. If those disagree, a rule-set bump
 * silently rewrites verdicts that ingest had got right, and only for the assets whose derivation touched whatever
 * differs.
 *
 * <p>
 * <b>The stored fixture is folded, never hand-typed, and that is the point of the test.</b> Writing
 * {@code new CryptoAssetIdentityFields(..., "X-Wing", ...)} by hand would pass while the real thing failed: the column
 * holds {@link CryptoAssetIdentityFields#normalized()}'s output, which lowercases the family, and
 * {@code AssetNormalizer} compares family tokens case-sensitively -- {@code HYBRID_FAMILIES.contains(winner)} against
 * {@code Set.of("X-Wing")}. A folded {@code x-wing} therefore took the non-hybrid scan path and re-derived different
 * components, so the sweep disagreed with ingest about exactly the hybrids these rules exist to catch. Building the
 * fixture through the real fold is what makes the test able to fail.
 */
class PqcParityTest {

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
    private final PqcEvaluator evaluator = new PqcEvaluator(normalizer);

    static List<String> assets() {
        return List
                .of("RSA-2048", "RSA", "ECDSA-P-256", "Ed25519", "AES-256-GCM", "SHA-256", "SHA-512/224", "DES", "MD5",
                        "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s", "Kyber768", "Dilithium3", "SIKEp434",
                        "Falcon-512", "FN-DSA-512", "X25519-ML-KEM-768", "X25519-Kyber768", "X-Wing", "GOST",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "Acme Proprietary Wrap", "HMAC-SHA256", "3DES-CMAC",
                        "ChaCha20-Poly1305", "XMSS-SHA2_10_256", "HSS-LMS", "bcrypt", "Classic McEliece 348864");
    }

    @ParameterizedTest
    @MethodSource("assets")
    void bothInputShapesReachTheSameVerdict(String name) {
        JsonNode component = PqcEvaluatorTest.algorithm(name);
        JsonNode properties = component.get("cryptoProperties");
        NormalizedAsset asset = normalizer.normalize(component).asset();

        PqcDecision fromIngest = evaluator
                .evaluate(evaluator.fromNormalized(asset, properties),
                        PqcEvaluator.nistQuantumSecurityLevel(properties));
        PqcDecision fromSweep = evaluator
                .evaluate(evaluator.fromStoredRow(storedRow(asset), properties),
                        PqcEvaluator.nistQuantumSecurityLevel(properties));

        assertThat(fromSweep.verdict()).describedAs("verdict for %s", name).isEqualTo(fromIngest.verdict());
        assertThat(fromSweep.ruleId()).describedAs("rule id for %s", name).isEqualTo(fromIngest.ruleId());
        assertThat(fromSweep.evaluatedFields())
                .describedAs("evaluated fields for %s", name)
                .isEqualTo(fromIngest.evaluatedFields());
    }

    /**
     * The hybrid case stated on its own, because it is the one the sweep has to re-derive rather than read: the
     * components live on {@link NormalizedAsset} alone and have no column, deliberately -- they are out-of-key by
     * construction, and adding a column would be a schema change with an identity fence and a merge election resting on
     * the shipped column set.
     */
    @Test
    void theSweepReDerivesAHybridsComponentsRatherThanReadingThem() {
        JsonNode component = PqcEvaluatorTest.algorithm("X25519-ML-KEM-768");
        NormalizedAsset asset = normalizer.normalize(component).asset();

        PqcRuleInput ingestShape = evaluator.fromNormalized(asset, component.get("cryptoProperties"));
        PqcRuleInput sweepShape = evaluator.fromStoredRow(storedRow(asset), component.get("cryptoProperties"));

        assertThat(ingestShape.hybridComponents()).isNotEmpty();
        assertThat(sweepShape.hybridComponents())
                .describedAs("re-derived from the stored, folded family and name")
                .isEqualTo(ingestShape.hybridComponents());
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

    /** Exactly what ingest will store: the derivation mapped onto columns, then folded by the column's own rule. */
    private static CryptoAssetIdentityFields storedRow(NormalizedAsset asset) {
        return CryptoAssetIdentityFields.of(PqcEvaluator.assetTypeOf(asset.assetType()), asset).normalized();
    }
}
