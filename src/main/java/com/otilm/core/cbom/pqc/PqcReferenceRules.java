package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Certificates and protocols, which carry no algorithm of their own: a certificate is as ready as the weaker of the key
 * it certifies and the algorithm it is signed with, a protocol as the weakest algorithm its cipher suites name.
 *
 * <p>
 * Each rule answers for itself and {@link PqcRuleOrder} picks the weakest: {@code notReady}, then {@code unknown}, then
 * {@code ready}, the key ahead of the signature at a tie. A reference that resolved to nothing, to an asset not yet
 * evaluated, or to one the question does not apply to, is a deferral under its own rule id: it may be the weak one, so
 * it outranks a resolved {@code ready} and yields to a resolved finding. Every certificate is signed, so one with no
 * signature algorithm recorded is not affirmed on its key alone, and a protocol is affirmed only once one of its
 * algorithms establishes a key.
 */
final class PqcReferenceRules {

    static final String CERT_SUBJECT_KEY = "CERT-SUBJECT-KEY";

    static final String CERT_SIGNATURE_ALGORITHM = "CERT-SIGNATURE-ALGORITHM";

    static final String CERT_REFERENCE_UNRESOLVED = "CERT-REFERENCE-UNRESOLVED";

    static final String CERT_NO_SIGNATURE_RECORDED = "CERT-NO-SIGNATURE-RECORDED";

    static final String CERT_NO_KEY_RECORDED = "CERT-NO-KEY-RECORDED";

    static final String PROTOCOL_CIPHER_SUITE = "PROTOCOL-CIPHER-SUITE";

    static final String PROTOCOL_SUITE_UNRESOLVED = "PROTOCOL-SUITE-UNRESOLVED";

    static final String PROTOCOL_NO_KEY_EXCHANGE = "PROTOCOL-NO-KEY-EXCHANGE";

    static final String PROTOCOL_NO_SUITES = "PROTOCOL-NO-SUITES";

    /** The CycloneDX primitives that establish a key, as the primitive column stores them. */
    private static final Set<String> KEY_ESTABLISHMENT = Set.of("key-agree", "kem");

    private static final List<String> CERTIFICATE_RESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.SUBJECT_PUBLIC_KEY_REF, PqcRules.SIGNATURE_ALGORITHM_REF,
                    PqcRules.REFERENCED_RULE_ID);

    private static final List<String> CERTIFICATE_UNRESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.SUBJECT_PUBLIC_KEY_REF, PqcRules.SIGNATURE_ALGORITHM_REF,
                    PqcRules.UNRESOLVED_REFS);

    private static final List<String> PROTOCOL_RESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.CIPHER_SUITES, PqcRules.CIPHER_SUITE_ALGORITHM_REFS,
                    PqcRules.CIPHER_SUITE, PqcRules.CIPHER_SUITE_ALGORITHM_REF, PqcRules.REFERENCED_RULE_ID);

    private static final List<String> PROTOCOL_UNRESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.CIPHER_SUITES, PqcRules.CIPHER_SUITE_ALGORITHM_REFS,
                    PqcRules.UNRESOLVED_REFS);

    /** The fields each rule reads, which a not-matched step shows. */
    static final Map<String, List<String>> READS_FIELDS = Map
            .of(CERT_SUBJECT_KEY, CERTIFICATE_RESOLVED_FIELDS, CERT_SIGNATURE_ALGORITHM, CERTIFICATE_RESOLVED_FIELDS,
                    CERT_REFERENCE_UNRESOLVED, CERTIFICATE_UNRESOLVED_FIELDS, CERT_NO_SIGNATURE_RECORDED,
                    List.of(PqcRules.ASSET_TYPE, PqcRules.SUBJECT_PUBLIC_KEY_REF), CERT_NO_KEY_RECORDED,
                    List.of(PqcRules.ASSET_TYPE, PqcRules.SIGNATURE_ALGORITHM_REF), PROTOCOL_CIPHER_SUITE,
                    PROTOCOL_RESOLVED_FIELDS, PROTOCOL_SUITE_UNRESOLVED, PROTOCOL_UNRESOLVED_FIELDS,
                    PROTOCOL_NO_KEY_EXCHANGE,
                    List.of(PqcRules.ASSET_TYPE, PqcRules.CIPHER_SUITES, PqcRules.CIPHER_SUITE_ALGORITHM_REFS),
                    PROTOCOL_NO_SUITES, List.of(PqcRules.ASSET_TYPE));

    private PqcReferenceRules() {
    }

    static boolean decides(CryptographicAssetType assetType) {
        return assetType == CryptographicAssetType.CERTIFICATE || assetType == CryptographicAssetType.PROTOCOL;
    }

    /** What one rule says about the asset's references, or {@code null} when its condition does not hold. */
    static PqcDecision candidate(String ruleId, PqcRuleInput input, Integer level, PqcReferences references) {
        return input.assetType() == CryptographicAssetType.CERTIFICATE
                ? certificate(ruleId, input, level, references)
                : protocol(ruleId, input, level, references);
    }

    private static PqcDecision certificate(String ruleId, PqcRuleInput input, Integer level, PqcReferences references) {
        Contribution key = Contribution.of(references.subjectKeys());
        Contribution signature = Contribution.of(references.signatureAlgorithms());
        return switch (ruleId) {
            case CERT_SUBJECT_KEY -> key.resolved == null
                    ? null
                    : resolved(CERT_SUBJECT_KEY, "The certificate is as ready as the key it certifies", key.resolved,
                            CERTIFICATE_RESOLVED_FIELDS, input, level, references);
            case CERT_SIGNATURE_ALGORITHM -> signature.resolved == null
                    ? null
                    : resolved(CERT_SIGNATURE_ALGORITHM,
                            "The certificate is as ready as the algorithm it is signed with", signature.resolved,
                            CERTIFICATE_RESOLVED_FIELDS, input, level, references);
            case CERT_REFERENCE_UNRESOLVED -> !key.unresolved && !signature.unresolved
                    ? null
                    : deferred(CERT_REFERENCE_UNRESOLVED,
                            "The certificate names a key or signature algorithm that resolved to no evaluated "
                                    + "inventory asset, so its readiness cannot be affirmed",
                            CERTIFICATE_UNRESOLVED_FIELDS, input, level, references);
            case CERT_NO_SIGNATURE_RECORDED -> !key.recorded() || signature.recorded()
                    ? null
                    : deferred(CERT_NO_SIGNATURE_RECORDED,
                            "The certificate records no signature algorithm, which may be weaker than the key it "
                                    + "certifies, so its readiness cannot be affirmed",
                            READS_FIELDS.get(CERT_NO_SIGNATURE_RECORDED), input, level, references);
            case CERT_NO_KEY_RECORDED -> key.recorded()
                    ? null
                    : deferred(CERT_NO_KEY_RECORDED,
                            "The certificate records no key it certifies, so its readiness cannot be affirmed",
                            READS_FIELDS.get(CERT_NO_KEY_RECORDED), input, level, references);
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a certificate rule");
        };
    }

    private static PqcDecision protocol(String ruleId, PqcRuleInput input, Integer level, PqcReferences references) {
        List<PqcReferences.Reference> algorithms = references.suiteAlgorithms();
        Optional<PqcReferences.Reference> weakest = weakestResolved(algorithms);
        boolean unresolved = algorithms.stream().anyMatch(reference -> !reference.resolved());
        return switch (ruleId) {
            case PROTOCOL_CIPHER_SUITE -> weakest
                    .map(deciding -> resolved(PROTOCOL_CIPHER_SUITE,
                            "A protocol is as ready as the weakest algorithm its cipher suites name", deciding,
                            PROTOCOL_RESOLVED_FIELDS, input, level, references))
                    .orElse(null);
            case PROTOCOL_SUITE_UNRESOLVED -> !unresolved
                    ? null
                    : deferred(PROTOCOL_SUITE_UNRESOLVED,
                            "A cipher suite names an algorithm that resolved to no evaluated inventory asset, so the "
                                    + "protocol's readiness cannot be affirmed",
                            PROTOCOL_UNRESOLVED_FIELDS, input, level, references);
            case PROTOCOL_NO_KEY_EXCHANGE -> !everyResolvedIsReady(weakest, unresolved) || establishesAKey(algorithms)
                    ? null
                    : deferred(PROTOCOL_NO_KEY_EXCHANGE,
                            "Every algorithm the cipher suites name is ready, but none of them establishes a key, "
                                    + "which the protocol negotiates separately and may be vulnerable",
                            READS_FIELDS.get(PROTOCOL_NO_KEY_EXCHANGE), input, level, references);
            case PROTOCOL_NO_SUITES ->
                !algorithms.isEmpty()
                        ? null
                        : deferred(PROTOCOL_NO_SUITES,
                                "The protocol records no cipher suite that names an algorithm, so its readiness cannot "
                                        + "be affirmed",
                                READS_FIELDS.get(PROTOCOL_NO_SUITES), input, level, references);
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a protocol rule");
        };
    }

    /** Whether the suites' algorithms all resolved and the weakest of them is ready. */
    private static boolean everyResolvedIsReady(Optional<PqcReferences.Reference> weakest, boolean unresolved) {
        return weakest.isPresent() && !unresolved && weakest.get().targetVerdict() == PqcVerdict.READY;
    }

    /**
     * Whether a resolved algorithm is a key agreement or a KEM. A TLS 1.3 suite names only its AEAD cipher and hash --
     * the key exchange is negotiated apart from it -- so a protocol whose suites are all ready says nothing yet about
     * the harvest-now-decrypt-later risk the verdict exists for.
     */
    private static boolean establishesAKey(List<PqcReferences.Reference> algorithms) {
        return algorithms
                .stream()
                .filter(PqcReferences.Reference::resolved)
                .anyMatch(reference -> reference.targetPrimitive() != null
                        && KEY_ESTABLISHMENT.contains(reference.targetPrimitive()));
    }

    /** The first reference, in suite order, that attains the weakest resolved verdict. */
    private static Optional<PqcReferences.Reference> weakestResolved(List<PqcReferences.Reference> references) {
        return references
                .stream()
                .filter(PqcReferences.Reference::resolved)
                .min(Comparator.comparingInt(reference -> PqcRuleOrder.rank(reference.targetVerdict())));
    }

    /** Why a rule's condition did not hold, in terms of this asset's references. */
    static String notMatched(String ruleId, PqcReferences references) {
        Contribution key = Contribution.of(references.subjectKeys());
        Contribution signature = Contribution.of(references.signatureAlgorithms());
        List<PqcReferences.Reference> algorithms = references.suiteAlgorithms();
        return switch (ruleId) {
            case CERT_SUBJECT_KEY -> key.recorded()
                    ? "The certified key resolved to no evaluated inventory asset"
                    : "No certified key is recorded";
            case CERT_SIGNATURE_ALGORITHM -> signature.recorded()
                    ? "The signature algorithm resolved to no evaluated inventory asset"
                    : "No signature algorithm is recorded";
            case CERT_REFERENCE_UNRESOLVED -> "Every recorded reference resolved";
            case CERT_NO_SIGNATURE_RECORDED ->
                signature.recorded() ? "A signature algorithm is recorded" : "No certified key is recorded";
            case CERT_NO_KEY_RECORDED -> "A certified key is recorded";
            case PROTOCOL_CIPHER_SUITE -> "No cipher suite algorithm resolved to an evaluated inventory asset";
            case PROTOCOL_SUITE_UNRESOLVED -> "Every cipher suite algorithm resolved";
            case PROTOCOL_NO_KEY_EXCHANGE -> keyExchangeNotMatched(algorithms);
            case PROTOCOL_NO_SUITES -> "A cipher suite names an algorithm";
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a reference rule");
        };
    }

    private static String keyExchangeNotMatched(List<PqcReferences.Reference> algorithms) {
        Optional<PqcReferences.Reference> weakest = weakestResolved(algorithms);
        if (weakest.isEmpty()) {
            return "No cipher suite names an algorithm that resolved";
        }
        if (algorithms.stream().anyMatch(reference -> !reference.resolved())) {
            return "A cipher suite algorithm resolved to nothing, so not every algorithm is known to be ready";
        }
        return weakest.get().targetVerdict() == PqcVerdict.READY
                ? "A resolved algorithm establishes a key"
                : "An algorithm the cipher suites name is not ready";
    }

    /** The reference-side inputs, in {@link PqcRules#INPUT_FIELDS} order; absent ones omitted. */
    static Map<String, Object> inputs(PqcReferences references) {
        Map<String, Object> inputs = new LinkedHashMap<>();
        for (String field : List
                .of(PqcRules.SUBJECT_PUBLIC_KEY_REF, PqcRules.SIGNATURE_ALGORITHM_REF, PqcRules.CIPHER_SUITES,
                        PqcRules.CIPHER_SUITE_ALGORITHM_REFS, PqcRules.UNRESOLVED_REFS)) {
            putIfPresent(inputs, field, valueOf(field, references, null));
        }
        return inputs;
    }

    static Map<String, Object> evidence(List<String> fields, PqcRuleInput input, Integer level,
            PqcReferences references, PqcReferences.Reference deciding) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        for (String field : fields) {
            if (!PqcRules.EVIDENCE_FIELDS.contains(field)) {
                throw new IllegalStateException(
                        "A reference rule declares an evaluated field outside the allowlist: " + field);
            }
            Object value = PqcRules.ASSET_TYPE.equals(field)
                    ? input.assetType().getCode()
                    : valueOf(field, references, deciding);
            putIfPresent(evidence, field, value);
        }
        if (level != null) {
            evidence.put(PqcRules.NIST_QUANTUM_SECURITY_LEVEL, level);
        }
        return evidence;
    }

    private static Object valueOf(String field, PqcReferences references, PqcReferences.Reference deciding) {
        return switch (field) {
            case PqcRules.SUBJECT_PUBLIC_KEY_REF -> oneOrMany(refs(references.subjectKeys()));
            case PqcRules.SIGNATURE_ALGORITHM_REF -> oneOrMany(refs(references.signatureAlgorithms()));
            case PqcRules.CIPHER_SUITES -> references.cipherSuites();
            case PqcRules.CIPHER_SUITE_ALGORITHM_REFS -> refs(references.suiteAlgorithms());
            case PqcRules.UNRESOLVED_REFS -> Stream
                    .of(references.subjectKeys(), references.signatureAlgorithms(), references.suiteAlgorithms())
                    .flatMap(List::stream)
                    .filter(reference -> !reference.resolved())
                    .map(PqcReferences.Reference::ref)
                    .toList();
            case PqcRules.CIPHER_SUITE -> deciding == null ? null : deciding.suite();
            case PqcRules.CIPHER_SUITE_ALGORITHM_REF ->
                deciding == null || deciding.suite() == null ? null : deciding.ref();
            case PqcRules.REFERENCED_RULE_ID -> deciding == null ? null : deciding.targetRuleId();
            default -> throw new IllegalStateException("Unhandled reference field: " + field);
        };
    }

    private static PqcDecision resolved(String ruleId, String reason, PqcReferences.Reference deciding,
            List<String> fields, PqcRuleInput input, Integer level, PqcReferences references) {
        return new PqcDecision(deciding.targetVerdict(), ruleId, reason,
                evidence(fields, input, level, references, deciding), deciding.target());
    }

    private static PqcDecision deferred(String ruleId, String reason, List<String> fields, PqcRuleInput input,
            Integer level, PqcReferences references) {
        return new PqcDecision(PqcVerdict.UNKNOWN, ruleId, reason, evidence(fields, input, level, references, null));
    }

    private static List<String> refs(List<PqcReferences.Reference> references) {
        return references.stream().map(PqcReferences.Reference::ref).toList();
    }

    private static Object oneOrMany(List<String> refs) {
        return refs.size() == 1 ? refs.get(0) : refs;
    }

    private static void putIfPresent(Map<String, Object> map, String field, Object value) {
        if (value != null && !(value instanceof List<?> list && list.isEmpty())) {
            map.put(field, value);
        }
    }

    /**
     * One of a certificate's two references. More than one of a kind is ambiguous, which the ingest already resolved to
     * nothing.
     *
     * @param resolved the reference that decides, or null
     * @param unresolved whether something was recorded that did not resolve
     */
    private record Contribution(PqcReferences.Reference resolved, boolean unresolved) {

        static Contribution of(List<PqcReferences.Reference> references) {
            if (references.size() == 1 && references.get(0).resolved()) {
                return new Contribution(references.get(0), false);
            }
            return new Contribution(null, !references.isEmpty());
        }

        boolean recorded() {
            return resolved != null || unresolved;
        }
    }
}
