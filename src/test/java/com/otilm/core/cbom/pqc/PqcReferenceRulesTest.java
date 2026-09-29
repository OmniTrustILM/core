package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * A certificate is as ready as the weaker of its key and signature algorithm, a protocol as the weakest algorithm its
 * cipher suites name; a reference that resolved to nothing may be the weak one. Every case also proves the explanation
 * agrees, through {@link PqcExplanationTest#assertExplains}.
 */
class PqcReferenceRulesTest {

    private static final UUID KEY = UUID.fromString("00000000-0000-4000-8000-000000000001");

    private static final UUID SIGNATURE = UUID.fromString("00000000-0000-4000-8000-000000000002");

    private static final UUID AES = UUID.fromString("00000000-0000-4000-8000-000000000003");

    private static final UUID RSA = UUID.fromString("00000000-0000-4000-8000-000000000004");

    private final PqcEvaluator evaluator = new PqcEvaluator(new AssetNormalizer(IdentityTables.load()));

    @Test
    void aWeakKeyDecidesACertificate() {
        PqcDecision decision = certificate(key(PqcVerdict.NOT_READY), signature(PqcVerdict.READY));

        assertThat(decision.ruleId()).isEqualTo("CERT-SUBJECT-KEY");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(decision.referencedAssetUuid()).isEqualTo(KEY);
        assertThat(decision.evaluatedFields())
                .containsEntry("assetType", "certificate")
                .containsEntry("subjectPublicKeyRef", "key-ref")
                .containsEntry("signatureAlgorithmRef", "sig-ref")
                .containsEntry("referencedRuleId", "TARGET-RULE");
    }

    @Test
    void aSignatureWeakerThanTheKeyDecidesACertificate() {
        PqcDecision decision = certificate(key(PqcVerdict.READY), signature(PqcVerdict.NOT_READY));

        assertThat(decision.ruleId()).isEqualTo("CERT-SIGNATURE-ALGORITHM");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(decision.referencedAssetUuid()).isEqualTo(SIGNATURE);
    }

    @Test
    void theKeyDecidesATie() {
        assertThat(certificate(key(PqcVerdict.READY), signature(PqcVerdict.READY)).ruleId())
                .isEqualTo("CERT-SUBJECT-KEY");
    }

    /** Every certificate is signed, so a ready key with no signature algorithm recorded cannot be affirmed. */
    @Test
    void aReadyKeyWithNoSignatureRecordedIsDeferredUnderItsOwnRuleId() {
        PqcDecision decision = certificate(key(PqcVerdict.READY));

        assertThat(decision.ruleId()).isEqualTo("CERT-NO-SIGNATURE-RECORDED");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(certificate(key(PqcVerdict.NOT_READY)).ruleId())
                .describedAs("a finding still reaches the row")
                .isEqualTo("CERT-SUBJECT-KEY");
    }

    /** A ready key beside a signature algorithm that resolved to nothing cannot be affirmed. */
    @Test
    void anUnresolvedReferenceDefersAReadyCertificate() {
        PqcDecision decision = certificate(key(PqcVerdict.READY),
                dangling(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "gone"));

        assertThat(decision.ruleId()).isEqualTo("CERT-REFERENCE-UNRESOLVED");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(decision.referencedAssetUuid()).isNull();
        assertThat(decision.evaluatedFields()).containsEntry("unresolvedRefs", List.of("gone"));
    }

    /** A finding reaches the row even when the key is missing. */
    @Test
    void aWeakSignatureDecidesACertificateThatRecordsNoKey() {
        assertThat(certificate(signature(PqcVerdict.NOT_READY)).ruleId()).isEqualTo("CERT-SIGNATURE-ALGORITHM");
        assertThat(certificate(signature(PqcVerdict.READY)).ruleId()).isEqualTo("CERT-NO-KEY-RECORDED");
    }

    /** A target the question does not apply to, or one never evaluated, is no answer about the certificate. */
    @Test
    void aNotApplicableOrUnevaluatedTargetCountsAsUnresolved() {
        assertThat(certificate(key(PqcVerdict.NOT_APPLICABLE)).ruleId()).isEqualTo("CERT-REFERENCE-UNRESOLVED");
        assertThat(certificate(key(null)).ruleId()).isEqualTo("CERT-REFERENCE-UNRESOLVED");
    }

    /** One hop: a key that is itself a certificate would let two referrers re-offer each other for ever. */
    @Test
    void aReferrerIsNeverATarget() {
        PqcReferences.Reference certificateTarget = new PqcReferences.Reference(
                CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY, "key-ref", null, KEY, CryptographicAssetType.CERTIFICATE,
                PqcVerdict.NOT_READY, "CERT-SUBJECT-KEY");

        assertThat(certificate(certificateTarget).ruleId()).isEqualTo("CERT-REFERENCE-UNRESOLVED");
    }

    @Test
    void theWeakestSuiteAlgorithmDecidesAProtocol() {
        PqcDecision decision = protocol(suite(AES, PqcVerdict.READY, "aes"), suite(RSA, PqcVerdict.NOT_READY, "rsa"),
                dangling(CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM, "gone"));

        assertThat(decision.ruleId()).isEqualTo("PROTOCOL-CIPHER-SUITE");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(decision.referencedAssetUuid()).isEqualTo(RSA);
        assertThat(decision.evaluatedFields())
                .containsEntry("cipherSuites", List.of("0x1301"))
                .containsEntry("cipherSuiteAlgorithmRefs", List.of("aes", "rsa", "gone"))
                .containsEntry("cipherSuite", "0x1301")
                .containsEntry("cipherSuiteAlgorithmRef", "rsa");
    }

    @Test
    void anUnresolvedAlgorithmDefersAnOtherwiseReadyProtocol() {
        assertThat(protocol(keyExchange(PqcVerdict.READY), suite(AES, PqcVerdict.READY, "aes")).verdict())
                .isEqualTo(PqcVerdict.READY);
        PqcDecision decision = protocol(keyExchange(PqcVerdict.READY), suite(AES, PqcVerdict.READY, "aes"),
                dangling(CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM, "gone"));
        assertThat(decision.ruleId()).isEqualTo("PROTOCOL-SUITE-UNRESOLVED");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
    }

    /**
     * A TLS 1.3 suite names only its AEAD cipher and hash; the key exchange is negotiated apart from it. Ready ciphers
     * alone say nothing about the harvest-now-decrypt-later risk, so the protocol defers until a key exchange is named.
     */
    @Test
    void aProtocolWhoseReadyAlgorithmsEstablishNoKeyIsDeferred() {
        PqcDecision decision = protocol(suite(AES, PqcVerdict.READY, "aes"), suite(RSA, PqcVerdict.READY, "sha"));

        assertThat(decision.ruleId()).isEqualTo("PROTOCOL-NO-KEY-EXCHANGE");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(protocol(suite(AES, PqcVerdict.NOT_READY, "des")).ruleId())
                .describedAs("a weak cipher still decides without a key exchange")
                .isEqualTo("PROTOCOL-CIPHER-SUITE");
    }

    /** A step before the decider names what actually kept it from deciding. */
    @Test
    void aNotMatchedStepSaysWhyForTheReferencesTheAssetHas() {
        assertThat(stepMessage(CryptographicAssetType.CERTIFICATE, "CERT-SUBJECT-KEY", key(PqcVerdict.READY),
                dangling(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "gone")))
                .isEqualTo("The signature algorithm resolved to no evaluated inventory asset and may be weaker than "
                        + "the certified key");
        assertThat(stepMessage(CryptographicAssetType.CERTIFICATE, "CERT-SIGNATURE-ALGORITHM",
                signature(PqcVerdict.READY)))
                .isEqualTo("No certified key is recorded to weigh the signature algorithm " + "against");
        assertThat(stepMessage(CryptographicAssetType.PROTOCOL, "PROTOCOL-CIPHER-SUITE",
                suite(AES, PqcVerdict.READY, "aes")))
                .isEqualTo("Every resolved algorithm is ready, but none of them establishes a key");
    }

    private String stepMessage(CryptographicAssetType type, String ruleId, PqcReferences.Reference... references) {
        return evaluator
                .explain(input(type), null, references(references))
                .steps()
                .stream()
                .filter(step -> step.ruleId().equals(ruleId))
                .findFirst()
                .orElseThrow()
                .message();
    }

    /** Two keys of one certificate name nothing, whatever each resolves to, rather than letting order decide. */
    @Test
    void twoKeysOfOneCertificateAreUnresolved() {
        PqcReferences.Reference otherKey = new PqcReferences.Reference(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY,
                "other-key", null, RSA, CryptographicAssetType.RELATED_CRYPTO_MATERIAL, PqcVerdict.NOT_READY, "R");

        assertThat(certificate(key(PqcVerdict.READY), otherKey).ruleId()).isEqualTo("CERT-REFERENCE-UNRESOLVED");
    }

    /** An unknown key is the weaker of the two and decides; the tie rule is not what picks it. */
    @Test
    void anUnknownKeyDecidesBesideAReadySignature() {
        PqcDecision decision = certificate(key(PqcVerdict.UNKNOWN), signature(PqcVerdict.READY));

        assertThat(decision.ruleId()).isEqualTo("CERT-SUBJECT-KEY");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
    }

    @Test
    void aProtocolTargetTheQuestionDoesNotApplyToOrThatIsItselfAReferrerIsUnresolved() {
        PqcReferences.Reference notApplicable = suite(AES, PqcVerdict.NOT_APPLICABLE, "aes");
        PqcReferences.Reference referrer = new PqcReferences.Reference(CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM,
                "tls", "0x1301", RSA, CryptographicAssetType.PROTOCOL, PqcVerdict.NOT_READY, "PROTOCOL-CIPHER-SUITE");

        assertThat(protocol(notApplicable).ruleId()).isEqualTo("PROTOCOL-SUITE-UNRESOLVED");
        assertThat(protocol(referrer).ruleId()).isEqualTo("PROTOCOL-SUITE-UNRESOLVED");
    }

    /** Among equally weak algorithms the first in suite order is named, so the answer does not depend on the read. */
    @Test
    void theFirstOfEquallyWeakSuiteAlgorithmsIsTheOneNamed() {
        PqcDecision decision = protocol(suite(AES, PqcVerdict.NOT_READY, "first"),
                suite(RSA, PqcVerdict.NOT_READY, "second"));

        assertThat(decision.referencedAssetUuid()).isEqualTo(AES);
        assertThat(decision.evaluatedFields()).containsEntry("cipherSuiteAlgorithmRef", "first");
    }

    /** The basis is the string the sweep's staleness arm rebuilds in SQL, so its spelling is pinned here. */
    @Test
    void theReferenceBasisNamesEachTargetAndTheVerdictItHeld() {
        assertThat(references(key(PqcVerdict.READY), dangling(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "gone"))
                .basis()).isEqualTo(KEY + ":READY:TARGET-RULE,::");
        assertThat(PqcReferences.of(List.of(), List.of()).basis()).isNull();
    }

    @Test
    void aResolvedStepCarriesTheAssetItCarriedTheVerdictFrom() {
        PqcRuleInput input = input(CryptographicAssetType.CERTIFICATE);
        PqcReferences references = references(key(PqcVerdict.READY), signature(PqcVerdict.NOT_READY));

        PqcExplanation explanation = evaluator.explain(input, null, references);

        assertThat(explanation.steps())
                .extracting(PqcExplanation.Step::ruleId, PqcExplanation.Step::outcome)
                .containsExactly(tuple("CERT-SUBJECT-KEY", PqcExplanationStepOutcome.NOT_MATCHED),
                        tuple("CERT-SIGNATURE-ALGORITHM", PqcExplanationStepOutcome.RESOLVED),
                        tuple("CERT-REFERENCE-UNRESOLVED", PqcExplanationStepOutcome.NOT_REACHED),
                        tuple("CERT-NO-SIGNATURE-RECORDED", PqcExplanationStepOutcome.NOT_REACHED),
                        tuple("CERT-NO-KEY-RECORDED", PqcExplanationStepOutcome.NOT_REACHED));
        assertThat(explanation.steps().get(0).message())
                .isEqualTo("The signature algorithm is weaker than the certified key");
        assertThat(explanation.steps().get(1).referencedAssetUuid()).isEqualTo(SIGNATURE);
        assertThat(PqcEvaluator.inputsOf(input, null, references))
                .containsEntry("subjectPublicKeyRef", "key-ref")
                .containsEntry("signatureAlgorithmRef", "sig-ref")
                .doesNotContainKey("referencedRuleId");
    }

    private PqcDecision certificate(PqcReferences.Reference... references) {
        return decide(CryptographicAssetType.CERTIFICATE, references);
    }

    private PqcDecision protocol(PqcReferences.Reference... references) {
        return decide(CryptographicAssetType.PROTOCOL, references);
    }

    private PqcDecision decide(CryptographicAssetType type, PqcReferences.Reference... references) {
        PqcRuleInput input = input(type);
        PqcReferences resolved = references(references);
        PqcDecision decision = evaluator.evaluate(input, null, resolved);
        PqcExplanationTest.assertExplains(evaluator.explain(input, null, resolved), decision, type);
        return decision;
    }

    private static PqcReferences references(PqcReferences.Reference... references) {
        List<String> suites = new ArrayList<>();
        for (PqcReferences.Reference reference : references) {
            if (reference.suite() != null && !suites.contains(reference.suite())) {
                suites.add(reference.suite());
            }
        }
        return PqcReferences.of(List.of(references), suites);
    }

    private static PqcRuleInput input(CryptographicAssetType type) {
        return new PqcRuleInput(type, null, null, null, null, null, null, "subject", List.of(), null, null);
    }

    private static PqcReferences.Reference key(PqcVerdict verdict) {
        return new PqcReferences.Reference(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY, "key-ref", null, KEY,
                CryptographicAssetType.RELATED_CRYPTO_MATERIAL, verdict, "TARGET-RULE");
    }

    private static PqcReferences.Reference signature(PqcVerdict verdict) {
        return new PqcReferences.Reference(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "sig-ref", null, SIGNATURE,
                CryptographicAssetType.ALGORITHM, verdict, "TARGET-RULE");
    }

    private static PqcReferences.Reference suite(UUID target, PqcVerdict verdict, String ref) {
        return new PqcReferences.Reference(CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM, ref, "0x1301", target,
                CryptographicAssetType.ALGORITHM, verdict, "TARGET-RULE");
    }

    private static PqcReferences.Reference keyExchange(PqcVerdict verdict) {
        return new PqcReferences.Reference(CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM, "kex", "0x1301", KEY,
                CryptographicAssetType.ALGORITHM, verdict, "TARGET-RULE", "key-agree");
    }

    private static PqcReferences.Reference dangling(CryptoAssetReferenceKind kind, String ref) {
        String suite = kind == CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM ? "0x1301" : null;
        return new PqcReferences.Reference(kind, ref, suite, null, null, null, null);
    }
}
