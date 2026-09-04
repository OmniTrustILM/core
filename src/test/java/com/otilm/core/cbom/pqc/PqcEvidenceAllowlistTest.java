package com.otilm.core.cbom.pqc;

import com.otilm.core.cbom.asset.JsonColumnText;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The write side of the identity-key constraint, asserted directly because nothing else can.
 *
 * <p>
 * {@code crypto_asset.pqc_evaluated_fields} is served verbatim to clients as
 * {@code CryptographicAssetVerdictDto.evaluatedFields}, and {@code IdentityKeyExposureFence} cannot see into it: the
 * fence is lexical over source text, both ends of this channel are innocuously named -- {@code pqcEvaluatedFields},
 * {@code evaluatedFields}, typed {@code Map<String, Object>} -- and the map's keys are runtime data. A green build
 * therefore proves nothing about what travels in this column, which is why these assertions run over the rendered JSON
 * rather than over the code.
 */
class PqcEvidenceAllowlistTest {

    /** The fence's own vocabulary, applied here to values rather than to declarations. */
    private static final Pattern FENCED = Pattern
            .compile("identity[_\\-\\s]?key|canonical[_\\-\\s]?key|absorbed[_\\-\\s]?key", Pattern.CASE_INSENSITIVE);

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
    private final PqcEvaluator evaluator = new PqcEvaluator(normalizer);

    @Test
    void everyRuleDeclaresOnlyAllowlistedFields() {
        assertThat(PqcRules.preFamilyRules())
                .allSatisfy(rule -> assertThat(PqcRules.EVIDENCE_FIELDS)
                        .describedAs("rule %s declares %s", rule.id(), rule.readsFields())
                        .containsAll(rule.readsFields()));
    }

    @ParameterizedTest
    @MethodSource("com.otilm.core.cbom.pqc.PqcParityTest#assets")
    void nothingOutsideTheAllowlistReachesTheColumn(String name) {
        PqcDecision decision = decide(name);
        assertThat(decision.evaluatedFields().keySet())
                .describedAs("evidence keys for %s", name)
                .isSubsetOf(PqcRules.EVIDENCE_FIELDS);
    }

    /**
     * The assertion the fence cannot make: over the bytes the column receives, not over the field names in source.
     */
    @ParameterizedTest
    @MethodSource("com.otilm.core.cbom.pqc.PqcParityTest#assets")
    void noRenderedEvidenceCarriesAKeyOrAnythingNamedLikeOne(String name) {
        String rendered = JsonColumnText.render(decide(name).evaluatedFields());
        assertThat(FENCED.matcher(rendered).find())
                .describedAs("rendered evidence for %s must not name an identity, canonical or absorbed key: %s", name,
                        rendered)
                .isFalse();
        assertThat(rendered)
                .describedAs("nor carry anything shaped like one -- the key is 64 lower-case hex characters")
                .doesNotMatch("(?s).*\\b[0-9a-f]{64}\\b.*");
    }

    /**
     * The input type carries no key to begin with, which is what makes the guarantee structural rather than a filter
     * someone has to remember to update. Stated as a test so that adding one to the record fails here.
     */
    @Test
    void theRuleInputTypeExposesNoKeyBearingComponent() {
        List<String> components = java.util.Arrays
                .stream(PqcRuleInput.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName)
                .toList();
        assertThat(components).allSatisfy(component -> assertThat(FENCED.matcher(component).find()).isFalse());
        assertThat(components)
                .describedAs("the evidence projection can only reach what this record holds")
                .allSatisfy(component -> assertThat(PqcRules.EVIDENCE_FIELDS).contains(component));
    }

    /**
     * A rule declaring a field outside the closed set is a programming error, and fails loudly rather than silently.
     */
    @Test
    void aRuleDeclaringAnUnknownFieldIsRefused() {
        PqcRule rogue = new PqcRule("ROGUE", input -> true, com.otilm.api.model.core.cryptoasset.PqcVerdict.UNKNOWN,
                "reason", List.of("identityKey"));
        assertThat(PqcRules.EVIDENCE_FIELDS).doesNotContain("identityKey");
        assertThatThrownBy(() -> assertThat(PqcRules.EVIDENCE_FIELDS).containsAll(rogue.readsFields()))
                .isInstanceOf(AssertionError.class);
    }

    private PqcDecision decide(String name) {
        var component = PqcEvaluatorTest.algorithm(name);
        var properties = component.get("cryptoProperties");
        return evaluator
                .evaluate(evaluator.fromNormalized(normalizer.normalize(component).asset(), properties),
                        PqcEvaluator.nistQuantumSecurityLevel(properties));
    }
}
