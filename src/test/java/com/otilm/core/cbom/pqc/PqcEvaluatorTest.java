package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The rule set's answers, driven through the real normalizer rather than through hand-built inputs.
 *
 * <p>
 * Every case starts from a CBOM component and runs the shipped derivation over it, because the interesting failures are
 * in what the derivation hands the rules -- a hybrid whose family is its classical half, a suite name that elects no
 * family -- and a hand-built {@link PqcRuleInput} would assert only that the rule table says what it says.
 */
class PqcEvaluatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
    private final PqcEvaluator evaluator = new PqcEvaluator(normalizer);

    // ---- the migration surface ------------------------------------------------------------------------------------

    @Test
    void everyRsaAssetIsNotReady() {
        assertThat(verdictOf(algorithm("RSA-2048")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(algorithm("RSA")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(algorithm("RSASSA-PSS")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(algorithm("RSA-2048")).ruleId()).isEqualTo("CLASSICAL-SHOR");
    }

    @Test
    void ellipticCurveIsNotReady() {
        assertThat(verdictOf(algorithm("ECDSA-P-256")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(algorithm("Ed25519")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
    }

    @Test
    void modernSymmetricAndHashAreReady() {
        assertThat(verdictOf(algorithm("AES-256-GCM")).verdict()).isEqualTo(PqcVerdict.READY);
        assertThat(verdictOf(algorithm("SHA-256")).verdict()).isEqualTo(PqcVerdict.READY);
        assertThat(verdictOf(algorithm("AES-256-GCM")).ruleId()).isEqualTo("SYMMETRIC-READY");
    }

    /**
     * An adjudication this rule set makes rather than inherits: reporting DES as post-quantum ready is true and
     * useless, so a classically broken primitive is not ready either -- under its own rule id, because the migration it
     * needs is a different one.
     */
    @Test
    void classicallyBrokenSymmetricIsNotReadyUnderItsOwnRuleId() {
        assertThat(verdictOf(algorithm("DES")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(algorithm("DES")).ruleId()).isEqualTo("CLASSICAL-LEGACY");
        assertThat(verdictOf(algorithm("MD5")).ruleId()).isEqualTo("CLASSICAL-LEGACY");
    }

    // ---- post-quantum ----------------------------------------------------------------------------------------------

    @Test
    void standardisedPostQuantumIsReady() {
        assertThat(verdictOf(algorithm("ML-KEM-768")).verdict()).isEqualTo(PqcVerdict.READY);
        assertThat(verdictOf(algorithm("ML-DSA-65")).verdict()).isEqualTo(PqcVerdict.READY);
        assertThat(verdictOf(algorithm("ML-KEM-768")).ruleId()).isEqualTo("PQC-STANDARDIZED");
    }

    @Test
    void preStandardCandidatesAreNotReady() {
        assertThat(verdictOf(algorithm("Kyber768")).verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(algorithm("Kyber768")).ruleId()).isEqualTo("PQC-PRESTANDARD");
        assertThat(verdictOf(algorithm("SIKEp434")).ruleId()).isEqualTo("PQC-BROKEN");
    }

    // ---- hybrids: the case the family column cannot answer alone ---------------------------------------------------

    /**
     * The rule that ruling (b) exists for. The identity grammar elects the classical half as the stored family, so a
     * family-first rule set would report a migrated asset as un-migrated.
     */
    @Test
    void aHybridIsNeverNotReadyOnItsClassicalHalf() {
        PqcDecision decision = verdictOf(algorithm("X25519-ML-KEM-768"));
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.READY);
        assertThat(decision.ruleId()).startsWith("PQC-HYBRID");
        assertThat(decision.evaluatedFields()).containsKey("hybridComponents");
    }

    /**
     * And the case a presence-only hybrid rule would get wrong: the post-quantum half is a superseded draft, not
     * wire-compatible with the scheme that replaced it, so the hybrid inherits its disposition rather than a blanket
     * ready.
     */
    @Test
    void aHybridInheritsItsPostQuantumComponentsDisposition() {
        PqcDecision decision = verdictOf(algorithm("X25519-Kyber768"));
        assertThat(decision.verdict())
                .describedAs("a hybrid over a pre-standard draft is not a completed migration")
                .isEqualTo(PqcVerdict.NOT_READY);
        assertThat(decision.ruleId()).isEqualTo("PQC-HYBRID-PQC-PRESTANDARD");
    }

    // ---- correctly outside the question ----------------------------------------------------------------------------

    @Test
    void aCipherSuiteNameIsNotApplicableRatherThanAnUnknownMiss() {
        PqcDecision decision = verdictOf(algorithm("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_APPLICABLE);
        assertThat(decision.ruleId()).isEqualTo("NAME-CIPHER-SUITE");
    }

    @Test
    void certificatesAreDeferredUnderTheirOwnRuleId() {
        PqcDecision decision = verdictOf(component("certificate", "www.example.test", "{}"));
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_APPLICABLE);
        assertThat(decision.ruleId())
                .describedAs("a deferral must be queryable apart from a genuine not-an-algorithm")
                .isEqualTo("CERT-DEFERRED-V1");
    }

    @Test
    void protocolsAreNotApplicable() {
        assertThat(verdictOf(component("protocol", "TLSv1.3", "{}")).ruleId()).isEqualTo("PROTOCOL-NOT-ALGORITHM");
    }

    // ---- related cryptographic material ----------------------------------------------------------------------------

    /**
     * <b>A finding, pinned rather than worked around.</b> The material tier derives no algorithm family at all --
     * {@code AssetNormalizer} leaves {@code family} null for every {@code related-crypto-material} component, with or
     * without an {@code algorithmRef} and with or without {@code algorithmProperties} -- so a private key whose own
     * name says {@code RSA-2048} reaches the rules with nothing to classify and lands on {@code unknown}.
     *
     * <p>
     * This is the same structural shape that defers certificates: the material's algorithm reaches it through
     * {@code algorithmRef}, which resolves against the document at ingest and not from a stored row. The planning
     * measurement behind putting material in scope counted family tokens in component <em>names</em>, which is not what
     * the pipeline stores. Recorded here so the next reader sees the real behaviour rather than the intention; whether
     * asymmetric material should be deferred like certificates, or gain a derivation, is an open adjudication.
     */
    @Test
    void asymmetricKeyMaterialCurrentlyReachesTheRulesWithNoFamily() {
        PqcDecision privateKey = verdictOf(material("RSA-2048", "private-key", 2048));
        assertThat(privateKey.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(privateKey.ruleId()).isEqualTo(PqcRules.FAMILY_UNRESOLVED);
        assertThat(verdictOf(material("ML-KEM-768", "public-key", null)).verdict()).isEqualTo(PqcVerdict.UNKNOWN);
    }

    @Test
    void aSymmetricKeyIsReadyOnlyWhenItSaysHowLongItIs() {
        assertThat(verdictOf(material("secret-key@1", "secret-key", 256)).verdict()).isEqualTo(PqcVerdict.READY);
        assertThat(verdictOf(material("secret-key@1", "secret-key", 256)).ruleId())
                .isEqualTo("MATERIAL-SYMMETRIC-READY");

        PqcDecision unsized = verdictOf(material("secret-key@2", "secret-key", null));
        assertThat(unsized.verdict())
                .describedAs("376 of 378 corpus secret keys name no family and 354 state no size; calling those ready "
                        + "would assert a strength nobody reported")
                .isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(verdictOf(material("secret-key@3", "secret-key", 64)).verdict()).isEqualTo(PqcVerdict.UNKNOWN);
    }

    @Test
    void materialThatIsNotAKeyIsNotApplicable() {
        assertThat(verdictOf(material("salt@1", "salt", 128)).ruleId()).isEqualTo("MATERIAL-NOT-KEY");
        assertThat(verdictOf(material("jwt-token", "token", null)).verdict()).isEqualTo(PqcVerdict.NOT_APPLICABLE);
        assertThat(verdictOf(material("truststore.p12", "key", null)).verdict()).isEqualTo(PqcVerdict.NOT_APPLICABLE);
    }

    /**
     * core#2196's ruling C10 keeps {@code unknown} as a value of the material-type vocabulary. This rule set is that
     * vocabulary's second reader and takes it as "the producer said nothing", so the row falls through to the family
     * rules rather than becoming a fourth arm of the material partition.
     */
    @Test
    void aMaterialTypeOfUnknownReadsAsNoTypeStated() {
        PqcDecision decision = verdictOf(material("secret-key@4", "unknown", 256));
        assertThat(decision.ruleId())
                .describedAs("a stated `unknown` must not be treated as a symmetric key that happens to declare a "
                        + "size; the producer said nothing, so the material arms do not apply")
                .isNotEqualTo("MATERIAL-SYMMETRIC-READY");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
    }

    // ---- what the rules genuinely cannot classify
    // --------------------------------------------------------------------

    @Test
    void aNameResolvingToNoRatifiedFamilyIsUnknown() {
        PqcDecision decision = verdictOf(algorithm("Acme Proprietary Wrap"));
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(decision.ruleId()).isEqualTo(PqcRules.FAMILY_UNRESOLVED);
    }

    /**
     * <b>A second finding, pinned rather than worked around.</b> FN-DSA -- the standardised name for Falcon -- is in no
     * ratified table, and the plan expected it to fall to {@code FAMILY-UNRESOLVED}. It does not: the name grammar's
     * loose form matches {@code DSA} <em>inside</em> {@code FN-DSA}, so the asset elects the classical DSA family and
     * reads its Falcon security level 512 as a key size. The verdict lands on {@code notReady}, which is the right
     * answer reached for entirely the wrong reason, and the stored row carries a wrong family and a wrong parameter set
     * that no verdict rule can repair.
     *
     * <p>
     * This is core#2196's ruling C7 -- guard the loose form where a token sits inside a longer family token -- which is
     * carried to core#2165 and unimplemented. The rule set does not paper over it: a special case here would make the
     * verdict disagree with the {@code algorithm_family} the inventory displays. Pinned so that implementing C7 turns
     * this test red and whoever does it sees what the verdict path expected.
     */
    @Test
    void fnDsaIsMisreadAsDsaByTheLooseNameGrammar() {
        PqcDecision decision = verdictOf(algorithm("FN-DSA-512"));
        assertThat(decision.ruleId())
                .describedAs("if this is now FAMILY-UNRESOLVED or a Falcon disposition, ruling C7 has landed and this "
                        + "test should be rewritten to assert the corrected behaviour")
                .isEqualTo("CLASSICAL-SHOR");
        assertThat(decision.evaluatedFields()).containsEntry("algorithmFamily", "DSA");
    }

    @Test
    void anAmbiguousFamilyIsUnknownRatherThanGuessed() {
        PqcDecision decision = verdictOf(algorithm("GOST"));
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(decision.ruleId()).isEqualTo("FAMILY-AMBIGUOUS");
    }

    // ---- helpers ---------------------------------------------------------------------------------------------------

    private PqcDecision verdictOf(JsonNode component) {
        JsonNode properties = component.get("cryptoProperties");
        return evaluator
                .evaluate(evaluator.fromNormalized(normalizer.normalize(component).asset(), properties),
                        PqcEvaluator.nistQuantumSecurityLevel(properties));
    }

    static JsonNode algorithm(String name) {
        return component("algorithm", name, "{\"algorithmProperties\":{}}");
    }

    static JsonNode material(String name, String type, Integer size) {
        String sizeMember = size == null ? "" : ",\"size\":" + size;
        return component("related-crypto-material", name,
                "{\"relatedCryptoMaterialProperties\":{\"type\":\"" + type + "\"" + sizeMember + "}}");
    }

    static JsonNode component(String assetType, String name, String extraProperties) {
        String properties = extraProperties.equals("{}")
                ? "{\"assetType\":\"" + assetType + "\"}"
                : "{\"assetType\":\"" + assetType + "\"," + extraProperties.substring(1);
        try {
            return MAPPER
                    .readTree("{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                            + properties + "}");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
