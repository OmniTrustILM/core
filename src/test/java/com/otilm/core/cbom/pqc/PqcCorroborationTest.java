package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code nistQuantumSecurityLevel} may corroborate a verdict and may never decide one.
 *
 * <p>
 * <b>Committed fixtures, not the corpus.</b> The values below are the disagreement the corpus actually holds -- SHA-384
 * carrying 0, 2 and 3 across producers, SHA-256 adding 5, and one producer writing a non-numeric string -- but a test
 * gated on {@code corpus.dir} is skipped in CI and would pin nothing. The acceptance criterion asks for this to be
 * pinned, so the disagreement is reproduced here as data.
 *
 * <p>
 * Note the level is per-payload rather than per-row: the merged view exposes only the elected source's value, so no
 * single stored row can exhibit the disagreement. That is precisely why a rule must not read it -- which producer wins
 * the merge election would otherwise decide the verdict.
 */
class PqcCorroborationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
    private final PqcEvaluator evaluator = new PqcEvaluator(normalizer);

    /** The observed producer values for one asset, plus absence and the non-numeric one. */
    static Stream<String> observedLevels() {
        return Stream.of(null, "0", "2", "3", "5", "\"not-a-number\"");
    }

    @ParameterizedTest
    @MethodSource("observedLevels")
    void theVerdictIsTheSameWhateverTheProducerClaimed(String level) {
        PqcDecision baseline = decide("SHA-384", null);
        PqcDecision withClaim = decide("SHA-384", level);

        assertThat(withClaim.verdict()).isEqualTo(baseline.verdict());
        assertThat(withClaim.ruleId())
                .describedAs("a disagreeing producer claim must not move the rule that fired")
                .isEqualTo(baseline.ruleId());
    }

    @ParameterizedTest
    @MethodSource("observedLevels")
    void aQuantumVulnerableAssetStaysNotReadyHoweverHighTheClaim(String level) {
        assertThat(decide("RSA-2048", level).ruleId()).isEqualTo("CLASSICAL-SHOR");
    }

    @Test
    void anIntegralLevelIsRecordedAsCorroboration() {
        assertThat(decide("SHA-384", "3").evaluatedFields()).containsEntry("nistQuantumSecurityLevel", 3);
    }

    /**
     * A non-integral value reads as absent rather than being carried through: it is producer text, and the wire field
     * it would land in promises a level.
     */
    @Test
    void aNonNumericLevelIsAbsentRatherThanProducerTextOnTheWire() {
        assertThat(decide("SHA-384", "\"not-a-number\"").evaluatedFields())
                .doesNotContainKey("nistQuantumSecurityLevel");
    }

    /**
     * {@code isIntegralNumber} accepts a long and {@code intValue} truncates it, so 4294967299 read as a plausible 3.
     */
    @Test
    void aLevelOutsideTheIntRangeIsAbsentRatherThanTruncated() {
        assertThat(decide("SHA-384", "4294967299").evaluatedFields()).doesNotContainKey("nistQuantumSecurityLevel");
    }

    /**
     * The structural half: no rule can read it, because the type a predicate sees does not hold it.
     *
     * <p>
     * Asserted as the exact component list rather than an absence. {@code doesNotContain} passes on an empty list, so
     * it would have held for a reason unrelated to the claim; naming every component also fails the moment one is
     * added, which is when someone would be about to let a rule read it.
     */
    @Test
    void theRuleInputTypeCannotSeeTheLevelAtAll() {
        assertThat(Arrays.stream(PqcRuleInput.class.getRecordComponents()).map(RecordComponent::getName).toList())
                .describedAs("keeping it out of the predicate's input is what makes 'corroborates, never decides' a "
                        + "property of the design rather than a convention")
                .containsExactly("assetType", "algorithmFamily", "parameterSet", "curve", "mode", "padding", "variant",
                        "name", "hybridComponents", "materialType", "materialSize");
    }

    private PqcDecision decide(String name, String level) {
        JsonNode component = componentWithLevel(name, level);
        JsonNode properties = component.get("cryptoProperties");
        return evaluator
                .evaluate(evaluator
                        .fromStoredRow(PqcEvaluatorTest.storedRow(normalizer.normalize(component).asset()), properties),
                        PqcEvaluator.nistQuantumSecurityLevel(properties));
    }

    private static JsonNode componentWithLevel(String name, String level) {
        String algorithmProperties = level == null ? "{}" : "{\"nistQuantumSecurityLevel\":" + level + "}";
        try {
            return MAPPER
                    .readTree("{\"type\":\"cryptographic-asset\",\"name\":\"" + name
                            + "\",\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":"
                            + algorithmProperties + "}}");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
