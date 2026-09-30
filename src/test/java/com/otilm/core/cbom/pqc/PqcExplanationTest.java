package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The explanation's shape. {@code explain} calls {@code evaluate}, so the two agree by construction; what running
 * {@link #assertExplains} over every case of {@link PqcEvaluatorTest} proves is that no input decides by a rule id the
 * catalogue does not list for its type -- which would throw -- and that the steps around the decision keep their
 * invariants.
 */
class PqcExplanationTest {

    private final PqcEvaluator evaluator = new PqcEvaluator(new AssetNormalizer(IdentityTables.load()));

    static void assertExplains(PqcExplanation explanation, PqcDecision decision, CryptographicAssetType assetType) {
        assertThat(explanation.decision()).isEqualTo(decision);
        List<PqcExplanation.Step> steps = explanation.steps();
        assertThat(steps.stream().map(step -> PqcRuleCatalog.entryIdOf(step.ruleId())))
                .containsExactlyElementsOf(
                        PqcRuleCatalog.servedFor(assetType).stream().map(PqcRuleCatalog.Entry::id).toList());
        List<PqcExplanation.Step> deciding = steps.stream().filter(PqcExplanationTest::decides).toList();
        assertThat(deciding).singleElement().satisfies(step -> {
            assertThat(step.ruleId()).isEqualTo(decision.ruleId());
            assertThat(step.verdict()).isEqualTo(decision.verdict());
            assertThat(step.message()).isEqualTo(decision.reason());
            assertThat(step.evaluatedFields()).isEqualTo(decision.evaluatedFields());
        });
        int decidedAt = steps.indexOf(deciding.get(0));
        assertThat(steps.subList(0, decidedAt))
                .allSatisfy(step -> assertThat(step.outcome()).isEqualTo(PqcExplanationStepOutcome.NOT_MATCHED));
        assertThat(steps.subList(decidedAt + 1, steps.size())).allSatisfy(step -> {
            assertThat(step.outcome()).isEqualTo(PqcExplanationStepOutcome.NOT_REACHED);
            assertThat(step.evaluatedFields()).isNull();
            assertThat(step.verdict()).isNull();
        });
        assertThat(steps).allSatisfy(step -> {
            assertThat(step.title()).isNotBlank();
            if (step.evaluatedFields() != null) {
                assertThat(PqcRules.EVIDENCE_FIELDS).containsAll(step.evaluatedFields().keySet());
            }
        });
    }

    private static boolean decides(PqcExplanation.Step step) {
        return step.outcome() == PqcExplanationStepOutcome.DECIDED
                || step.outcome() == PqcExplanationStepOutcome.RESOLVED;
    }

    @Test
    void everyCatalogueIdIsListedOnce() {
        Map<String, Long> counts = PqcRuleCatalog
                .entries()
                .stream()
                .collect(Collectors.groupingBy(PqcRuleCatalog.Entry::id, Collectors.counting()));
        assertThat(counts).allSatisfy((id, count) -> assertThat(count).describedAs(id).isEqualTo(1L));
    }

    /** A table rule missing from the catalogue would make every asset it decides unexplainable. */
    @Test
    void everyTableRuleHasACatalogueEntry() {
        List<String> tableIds = PqcRules
                .rulesFor(null, input -> true, input -> true)
                .stream()
                .map(PqcRule::id)
                .toList();
        assertThat(PqcRuleCatalog.entries().stream().map(PqcRuleCatalog.Entry::id)).containsAll(tableIds);
    }

    @Test
    void anAssetIsShownOnlyTheRulesItsTypeIsTestedAgainst() {
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.CERTIFICATE)).hasSize(5);
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.PROTOCOL)).hasSize(4);
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.UNROUTABLE)).hasSize(1);
        assertThat(PqcRuleCatalog.servedFor(null))
                .isEqualTo(PqcRuleCatalog.servedFor(CryptographicAssetType.UNROUTABLE));
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.ALGORITHM)).hasSize(19);
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.RELATED_CRYPTO_MATERIAL)).hasSize(21);
    }

    /**
     * Every id the coded paths can emit, independent of whether the corpus happens to reach it: the family
     * dispositions, their component variants, and the hybrid composed from any family, for both types the paths serve.
     */
    @Test
    void everyIdTheCodedPathsEmitHasAnEntryForBothTypesTheyServe() {
        List<String> emitted = new ArrayList<>();
        for (FamilyClass family : FamilyClass.values()) {
            emitted.add(family.ruleId());
            emitted.add(PqcRules.HYBRID + "-" + family.ruleId());
        }
        emitted
                .addAll(List
                        .of("CLASSICAL-LEGACY-COMPONENT", "CLASSICAL-SHOR-COMPONENT", "FAMILY-AMBIGUOUS-COMPONENT",
                                "PQC-HYBRID-UNRESOLVED", PqcRules.FAMILY_UNRESOLVED, "PQC-ONE-TIME-SIGNATURE",
                                "CONSTRUCTION-UNINSTANTIATED", "SYMMETRIC-UNDERSIZED"));
        for (CryptographicAssetType type : List
                .of(CryptographicAssetType.ALGORITHM, CryptographicAssetType.RELATED_CRYPTO_MATERIAL)) {
            List<String> served = PqcRuleCatalog.servedFor(type).stream().map(PqcRuleCatalog.Entry::id).toList();
            assertThat(emitted.stream().map(PqcRuleCatalog::entryIdOf))
                    .describedAs("served to %s", type)
                    .allMatch(served::contains);
        }
    }

    @Test
    void aComposedHybridIdIsListedUnderTheHybridEntry() {
        assertThat(PqcRuleCatalog.entryIdOf("PQC-HYBRID-PQC-STANDARDIZED")).isEqualTo(PqcRules.HYBRID);
        assertThat(PqcRuleCatalog.entryIdOf("PQC-HYBRID-UNRESOLVED")).isEqualTo("PQC-HYBRID-UNRESOLVED");
        assertThat(PqcRuleCatalog.entryIdOf("PQC-HYBRID-FAMILY")).isEqualTo("PQC-HYBRID-FAMILY");
    }

    /** A not-matched step shows what its rule reads; a not-reached one read nothing. */
    @Test
    void theStepsAroundTheDecisionCarryWhatTheirOutcomeAllows() {
        PqcRuleInput rsa = new PqcRuleInput(CryptographicAssetType.ALGORITHM, "RSA", 2048, null, null, null, null,
                "RSA-2048", List.of(), null, null);

        PqcExplanation explanation = evaluator.explain(rsa, 1);

        assertExplains(explanation, evaluator.evaluate(rsa, 1), CryptographicAssetType.ALGORITHM);
        PqcExplanation.Step first = explanation.steps().get(0);
        assertThat(first.ruleId()).isEqualTo("NAME-CIPHER-SUITE");
        assertThat(first.evaluatedFields())
                .containsEntry("assetType", "algorithm")
                .containsEntry("algorithmFamily", "RSA")
                .containsEntry("nistQuantumSecurityLevel", 1);
        assertThat(explanation.steps().stream().filter(step -> step.ruleId().equals("CLASSICAL-SHOR")))
                .singleElement()
                .satisfies(step -> assertThat(step.outcome()).isEqualTo(PqcExplanationStepOutcome.DECIDED));
    }

    @Test
    void theInputsAreEveryReadableValueTheAssetHas() {
        PqcRuleInput rsa = new PqcRuleInput(CryptographicAssetType.ALGORITHM, "RSA", 2048, null, null, null, null,
                "RSA-2048", List.of(), null, null);

        assertThat(PqcEvaluator.inputsOf(rsa, null, PqcReferences.NONE))
                .containsExactly(Map.entry("assetType", "algorithm"), Map.entry("algorithmFamily", "RSA"),
                        Map.entry("parameterSet", 2048), Map.entry("name", "RSA-2048"));
        Predicate<String> allowlisted = PqcRules.EVIDENCE_FIELDS::contains;
        assertThat(PqcRules.INPUT_FIELDS).allMatch(allowlisted);
    }
}
