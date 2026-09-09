package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.cbom.asset.JsonColumnText;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
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
        assertThat(PqcRules.rulesFor(normalizer))
                .allSatisfy(rule -> assertThat(PqcRules.EVIDENCE_FIELDS)
                        .describedAs("rule %s declares %s", rule.id(), rule.readsFields())
                        .containsAll(rule.readsFields()));
    }

    static List<String> algorithmNames() {
        return List
                .of("RSA-2048", "RSA", "ECDSA-P-256", "Ed25519", "AES-256-GCM", "SHA-256", "SHA-512/224", "DES", "MD5",
                        "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s", "Kyber768", "Dilithium3", "SIKEp434",
                        "Falcon-512", "FN-DSA-512", "X25519-ML-KEM-768", "X25519-Kyber768", "X-Wing", "GOST",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "Acme Proprietary Wrap", "HMAC-SHA256", "3DES-CMAC",
                        "ChaCha20-Poly1305", "XMSS-SHA2_10_256", "HSS-LMS", "bcrypt", "Classic McEliece 348864",
                        "X25519-ML-KEM-\uFF17\uFF16\uFF18", "RSA-\uFF12\uFF10\uFF14\uFF18", "\uFF32\uFF33\uFF21-2048");
    }

    /**
     * One algorithm name per rule family, plus the shapes an algorithm row lacks: the material and asset-type rules
     * read fields no algorithm row carries, so without these the allowlist was never driven through them.
     */
    static Stream<Arguments> components() {
        return Stream
                .concat(algorithmNames().stream().map(name -> Arguments.of(name, PqcEvaluatorTest.algorithm(name))),
                        Stream
                                .of(Arguments
                                        .of("secret-key of 256 bits",
                                                PqcEvaluatorTest.material("secret-key@1", "secret-key", 256)),
                                        Arguments
                                                .of("RSA-2048 private key",
                                                        PqcEvaluatorTest.material("RSA-2048", "private-key", 2048)),
                                        Arguments
                                                .of("certificate", PqcEvaluatorTest
                                                        .component("certificate", "www.example.test", "{}"))));
    }

    @ParameterizedTest
    @MethodSource("components")
    void nothingOutsideTheAllowlistReachesTheColumn(String name, JsonNode component) {
        PqcDecision decision = decide(component);
        assertThat(decision.evaluatedFields().keySet())
                .describedAs("evidence keys for %s", name)
                .isSubsetOf(PqcRules.EVIDENCE_FIELDS);
    }

    /**
     * The assertion the fence cannot make: over the bytes the column receives, not over the field names in source.
     *
     * <p>
     * <b>What is guaranteed, stated precisely.</b> Evidence values are producer text -- a name, a family, a curve --
     * and an earlier revision of this test asserted no rendered evidence could contain 64 hex characters, which reads
     * as "no producer string reaches the client" and is false: every value recorded here is drawn from a column the
     * detail endpoint already serves under its own name, so echoing one discloses nothing new. What must never appear
     * is a value <em>derived from</em> {@code crypto_asset.identity_key}, an alias canonical key or an absorbed key,
     * because core#2070's redaction ruling rests on those never leaving the database and the key is a hash over a
     * low-entropy pre-image. {@link #theRuleInputTypeExposesNoKeyBearingComponent} is what settles that, structurally.
     * The adversarial case below records the difference rather than pretending it away.
     */
    @ParameterizedTest
    @MethodSource("components")
    void noRenderedEvidenceNamesAKeyBearingField(String name, JsonNode component) {
        PqcDecision decision = decide(component);
        assertThat(JsonColumnText.render(decision.evaluatedFields())).isNotNull();
        // The keys, not the values: the keys are ours and closed, the values are producer text that a producer can
        // spell however it likes. Asserting the regex over the whole rendered blob reads as a guarantee about the
        // values, and anAdversarialProducerNameIsEchoedRatherThanLeaking shows that guarantee does not exist.
        assertThat(decision.evaluatedFields().keySet())
                .describedAs("evidence keys for %s", name)
                .allSatisfy(key -> assertThat(FENCED.matcher(key).find()).isFalse());
    }

    /**
     * A producer that names its asset like an identity key gets its own string back, and that is not a disclosure: the
     * same text is already served as the asset's {@code name}. Pinned so nobody re-derives the stronger claim from the
     * weaker test above.
     */
    @Test
    void anAdversarialProducerNameIsEchoedRatherThanLeaking() {
        String keyShaped = "identity key " + "a".repeat(64);
        PqcDecision decision = decide(PqcEvaluatorTest.algorithm(keyShaped));

        assertThat(decision.ruleId()).isEqualTo(PqcRules.FAMILY_UNRESOLVED);
        assertThat(decision.evaluatedFields())
                .describedAs("the producer's own name, folded, and nothing else")
                .containsEntry("name", keyShaped.toLowerCase(java.util.Locale.ROOT));
        assertThat(decision.evaluatedFields().keySet()).isSubsetOf(PqcRules.EVIDENCE_FIELDS);
    }

    /**
     * The input type carries no key to begin with, which is what makes the guarantee structural rather than a filter
     * someone has to remember to update. Stated as a test so that adding one to the record fails here.
     */
    @Test
    void theRuleInputTypeExposesNoKeyBearingComponent() {
        List<String> components = Arrays
                .stream(PqcRuleInput.class.getRecordComponents())
                .map(RecordComponent::getName)
                .toList();

        assertThat(components)
                .describedAs("no component may name a key, and the projection can only reach what this record holds")
                .isNotEmpty()
                .allSatisfy(component -> assertThat(FENCED.matcher(component).find()).isFalse())
                .allMatch(PqcRules.EVIDENCE_FIELDS::contains);
    }

    /**
     * A rule declaring a field outside the closed set is a programming error, and fails loudly rather than silently.
     */
    @Test
    void aRuleDeclaringAnUnknownFieldIsRefused() {
        assertThat(PqcRules.EVIDENCE_FIELDS).doesNotContain("identityKey");
        PqcRuleInput input = evaluator
                .fromStoredRow(PqcEvaluatorTest
                        .storedRow(normalizer.normalize(PqcEvaluatorTest.algorithm("RSA-2048")).asset()), null);
        List<String> rogueFields = List.of("identityKey");

        // The allowlist guard's own text, not the field name: the exhaustiveness default in the projection's switch
        // also throws with the field name in it, so matching on that let either guard be deleted alone.
        assertThatThrownBy(() -> PqcEvaluator.projectEvidence(rogueFields, input, null, "ROGUE"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("outside the allowlist")
                .hasMessageContaining("identityKey");
    }

    private PqcDecision decide(JsonNode component) {
        var properties = component.get("cryptoProperties");
        return evaluator
                .evaluate(evaluator
                        .fromStoredRow(PqcEvaluatorTest.storedRow(normalizer.normalize(component).asset()), properties),
                        PqcEvaluator.nistQuantumSecurityLevel(properties));
    }
}
