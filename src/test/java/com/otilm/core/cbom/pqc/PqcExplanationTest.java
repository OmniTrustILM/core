package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The explanation's shape. {@code explain} and {@code evaluate} select from the same candidates, so the two agree by
 * construction; what running {@link #assertExplains} over every case of {@link PqcEvaluatorTest} proves is that every
 * rule the catalogue lists for the type is reported as matched or not, that exactly one matched rule decides, and that
 * the decision is the one {@link PqcRuleOrder} selects from the matched steps.
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
        assertThat(steps).allSatisfy(step -> {
            assertThat(step.title()).isNotBlank();
            assertThat(step.outcome()).isNotEqualTo(PqcExplanationStepOutcome.NOT_REACHED);
            assertThat(step.evaluatedFields()).isNotNull();
            assertThat(PqcRules.EVIDENCE_FIELDS).containsAll(step.evaluatedFields().keySet());
            if (step.outcome() == PqcExplanationStepOutcome.NOT_MATCHED) {
                assertThat(step.verdict()).isNull();
            } else {
                assertThat(step.verdict()).isNotNull();
            }
        });
        assertSelected(steps, deciding.get(0), assetType);
    }

    /** The decided step is what the stated order picks from the matched steps, recomputed here from the steps. */
    private static void assertSelected(List<PqcExplanation.Step> steps, PqcExplanation.Step decided,
            CryptographicAssetType assetType) {
        List<PqcRuleCatalog.Entry> served = PqcRuleCatalog.servedFor(assetType);
        List<PqcExplanation.Step> matched = steps
                .stream()
                .filter(step -> step.outcome() != PqcExplanationStepOutcome.NOT_MATCHED)
                .toList();
        List<PqcExplanation.Step> exclusions = matched
                .stream()
                .filter(step -> tierOf(served, step) == PqcRuleCatalog.Tier.EXCLUSION)
                .toList();
        if (!exclusions.isEmpty()) {
            assertThat(decided).isSameAs(exclusions.get(0));
            return;
        }
        List<PqcExplanation.Step> findings = matched
                .stream()
                .filter(step -> tierOf(served, step) == PqcRuleCatalog.Tier.FINDING)
                .toList();
        if (findings.isEmpty()) {
            assertThat(tierOf(served, decided)).isEqualTo(PqcRuleCatalog.Tier.FALLBACK);
            return;
        }
        int weakest = findings.stream().mapToInt(step -> PqcRuleOrder.rank(step.verdict())).min().orElseThrow();
        assertThat(decided)
                .describedAs("the first matched finding of the weakest verdict decides")
                .isSameAs(findings
                        .stream()
                        .filter(step -> PqcRuleOrder.rank(step.verdict()) == weakest)
                        .findFirst()
                        .orElseThrow());
    }

    private static PqcRuleCatalog.Tier tierOf(List<PqcRuleCatalog.Entry> served, PqcExplanation.Step step) {
        String entryId = PqcRuleCatalog.entryIdOf(step.ruleId());
        return served.stream().filter(entry -> entry.id().equals(entryId)).findFirst().orElseThrow().tier();
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

    /** The exclusions are the rules that answer {@code notApplicable}, and nothing else is one. */
    @Test
    void theExclusionsAreExactlyTheNotApplicableRules() {
        List<String> notApplicable = PqcRules
                .rulesFor(null, input -> true, input -> true)
                .stream()
                .filter(rule -> rule.verdict() == PqcVerdict.NOT_APPLICABLE)
                .map(PqcRule::id)
                .toList();
        List<String> exclusions = PqcRuleCatalog
                .entries()
                .stream()
                .filter(entry -> entry.tier() == PqcRuleCatalog.Tier.EXCLUSION)
                .map(PqcRuleCatalog.Entry::id)
                .toList();
        assertThat(exclusions).containsExactlyInAnyOrderElementsOf(notApplicable);
        assertThat(PqcRuleCatalog.entries().stream().filter(entry -> entry.tier() == PqcRuleCatalog.Tier.FALLBACK))
                .extracting(PqcRuleCatalog.Entry::id)
                .containsExactly(PqcRules.FAMILY_UNRESOLVED);
    }

    @Test
    void anAssetIsShownOnlyTheRulesItsTypeIsTestedAgainst() {
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.CERTIFICATE)).hasSize(5);
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.PROTOCOL)).hasSize(4);
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.UNROUTABLE)).isEmpty();
        assertThat(PqcRuleCatalog.servedFor(null)).isEmpty();
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.ALGORITHM)).hasSize(20);
        assertThat(PqcRuleCatalog.servedFor(CryptographicAssetType.RELATED_CRYPTO_MATERIAL)).hasSize(22);
    }

    /** No rule is catalogued for the unroutable tier, which ingest no longer stores. */
    @Test
    void anUnroutableRowCannotBeEvaluated() {
        PqcRuleInput unroutable = new PqcRuleInput(CryptographicAssetType.UNROUTABLE, null, null, null, null, null,
                null, "Acme Wrap", List.of(), null, null, null);

        assertThatThrownBy(() -> evaluator.evaluate(unroutable, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("UNROUTABLE");
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
                        .of(PqcRules.CLASSICAL_LEGACY_COMPONENT, PqcRules.CLASSICAL_SHOR_COMPONENT,
                                PqcRules.FAMILY_AMBIGUOUS_COMPONENT, PqcRules.HYBRID_UNRESOLVED,
                                PqcRules.FAMILY_UNRESOLVED, PqcRules.ONE_TIME_SIGNATURE,
                                PqcRules.CONSTRUCTION_UNINSTANTIATED, PqcRules.PARAMETER_SET_UNREGISTERED,
                                PqcRules.SYMMETRIC_UNDERSIZED));
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

    /** A not-matched step shows what its rule reads; the deciding step shows what it read. */
    @Test
    void theStepsAroundTheDecisionCarryWhatTheirOutcomeAllows() {
        PqcRuleInput rsa = new PqcRuleInput(CryptographicAssetType.ALGORITHM, "RSA", 2048, null, null, null, null,
                "RSA-2048", List.of(), null, null, "pke");

        PqcExplanation explanation = evaluator.explain(rsa, 1);

        assertExplains(explanation, evaluator.evaluate(rsa, 1), CryptographicAssetType.ALGORITHM);
        PqcExplanation.Step first = explanation.steps().get(0);
        assertThat(first.ruleId()).isEqualTo(PqcRules.NAME_CIPHER_SUITE);
        assertThat(first.outcome()).isEqualTo(PqcExplanationStepOutcome.NOT_MATCHED);
        assertThat(first.evaluatedFields())
                .containsEntry("assetType", "algorithm")
                .containsEntry("algorithmFamily", "RSA")
                .containsEntry("nistQuantumSecurityLevel", 1);
        assertThat(explanation.steps().stream().filter(step -> step.ruleId().equals("CLASSICAL-SHOR")))
                .singleElement()
                .satisfies(step -> assertThat(step.outcome()).isEqualTo(PqcExplanationStepOutcome.DECIDED));
        assertThat(explanation.steps())
                .describedAs("a plain RSA key matches one rule and one only")
                .filteredOn(step -> step.outcome() != PqcExplanationStepOutcome.NOT_MATCHED)
                .hasSize(1);
    }

    /** A rule that also held is shown as matched, with its own verdict, beside the weaker one that decided. */
    @Test
    void aWeakerRuleDecidesAndTheStrongerOneThatAlsoHeldIsShownMatched() {
        PqcRuleInput oneTimeSignature = new PqcRuleInput(CryptographicAssetType.ALGORITHM, "LMS", null, null, null,
                null, "ots", "LM-OTS", List.of(), null, null, "signature");

        PqcExplanation explanation = evaluator.explain(oneTimeSignature, null);

        assertThat(explanation.decision().ruleId()).isEqualTo(PqcRules.ONE_TIME_SIGNATURE);
        assertThat(explanation.steps())
                .filteredOn(step -> step.ruleId().equals(FamilyClass.PQC_STANDARDIZED.ruleId()))
                .singleElement()
                .satisfies(step -> {
                    assertThat(step.outcome()).isEqualTo(PqcExplanationStepOutcome.MATCHED);
                    assertThat(step.verdict()).isEqualTo(PqcVerdict.READY);
                    assertThat(step.message()).isEqualTo(FamilyClass.PQC_STANDARDIZED.reason());
                    assertThat(step.evaluatedFields()).containsEntry("algorithmFamily", "LMS");
                });
    }

    @Test
    void theInputsAreEveryReadableValueTheAssetHas() {
        PqcRuleInput rsa = new PqcRuleInput(CryptographicAssetType.ALGORITHM, "RSA", 2048, null, null, null, null,
                "RSA-2048", List.of(), null, null, "pke");

        assertThat(PqcEvaluator.inputsOf(rsa, null, PqcReferences.NONE))
                .containsExactly(Map.entry("assetType", "algorithm"), Map.entry("algorithmFamily", "RSA"),
                        Map.entry("primitive", "pke"), Map.entry("parameterSet", 2048), Map.entry("name", "RSA-2048"));
        Predicate<String> allowlisted = PqcRules.EVIDENCE_FIELDS::contains;
        assertThat(PqcRules.INPUT_FIELDS).allMatch(allowlisted);
    }
}
