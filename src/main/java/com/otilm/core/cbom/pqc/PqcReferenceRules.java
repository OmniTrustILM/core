package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Certificates and protocols, which carry no algorithm of their own: a certificate is as ready as the weaker of the key
 * it certifies and the algorithm it is signed with, a protocol as the weakest algorithm its cipher suites name.
 *
 * <p>
 * Weaker is {@code notReady}, then {@code unknown}, then {@code ready}. A reference that resolved to nothing, to an
 * asset not yet evaluated, or to one the question does not apply to, counts as {@code unknown}: it may be the weak one.
 * So a resolved finding decides even beside an unresolved reference, while a resolved {@code ready} does not, and a
 * reference recorded and unresolved is a deferral under its own rule id, apart from "nothing recorded".
 */
final class PqcReferenceRules {

    static final String CERT_SUBJECT_KEY = "CERT-SUBJECT-KEY";

    static final String CERT_SIGNATURE_ALGORITHM = "CERT-SIGNATURE-ALGORITHM";

    static final String CERT_REFERENCE_UNRESOLVED = "CERT-REFERENCE-UNRESOLVED";

    static final String CERT_NO_KEY_RECORDED = "CERT-NO-KEY-RECORDED";

    static final String PROTOCOL_CIPHER_SUITE = "PROTOCOL-CIPHER-SUITE";

    static final String PROTOCOL_SUITE_UNRESOLVED = "PROTOCOL-SUITE-UNRESOLVED";

    static final String PROTOCOL_NO_SUITES = "PROTOCOL-NO-SUITES";

    private static final int UNRESOLVED_RANK = rank(PqcVerdict.UNKNOWN);

    private static final int ABSENT_RANK = rank(PqcVerdict.READY);

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
                    CERT_REFERENCE_UNRESOLVED, CERTIFICATE_UNRESOLVED_FIELDS, CERT_NO_KEY_RECORDED,
                    List.of(PqcRules.ASSET_TYPE, PqcRules.SIGNATURE_ALGORITHM_REF), PROTOCOL_CIPHER_SUITE,
                    PROTOCOL_RESOLVED_FIELDS, PROTOCOL_SUITE_UNRESOLVED, PROTOCOL_UNRESOLVED_FIELDS, PROTOCOL_NO_SUITES,
                    List.of(PqcRules.ASSET_TYPE));

    private PqcReferenceRules() {
    }

    static boolean decides(CryptographicAssetType assetType) {
        return assetType == CryptographicAssetType.CERTIFICATE || assetType == CryptographicAssetType.PROTOCOL;
    }

    static PqcDecision decide(PqcRuleInput input, Integer level, PqcReferences references) {
        return input.assetType() == CryptographicAssetType.CERTIFICATE
                ? certificate(input, level, references)
                : protocol(input, level, references);
    }

    private static PqcDecision certificate(PqcRuleInput input, Integer level, PqcReferences references) {
        Contribution key = Contribution.of(references.subjectKeys());
        Contribution signature = Contribution.of(references.signatureAlgorithms());
        if (key.resolved != null && rank(key.resolved.targetVerdict()) <= signature.rankAgainstKey()) {
            return resolved(CERT_SUBJECT_KEY,
                    "The certificate is as ready as the key it certifies, which is no stronger than its signature "
                            + "algorithm",
                    key.resolved, CERTIFICATE_RESOLVED_FIELDS, input, level, references);
        }
        if (signature.resolved != null && rank(signature.resolved.targetVerdict()) < key.rankAgainstSignature()) {
            return resolved(CERT_SIGNATURE_ALGORITHM,
                    "The certificate is signed with an algorithm weaker than the key it certifies, so the signature "
                            + "decides",
                    signature.resolved, CERTIFICATE_RESOLVED_FIELDS, input, level, references);
        }
        if (key.unresolved || signature.unresolved) {
            return deferred(CERT_REFERENCE_UNRESOLVED,
                    "The certificate names a key or signature algorithm that resolved to no evaluated inventory asset, "
                            + "so its readiness cannot be affirmed",
                    CERTIFICATE_UNRESOLVED_FIELDS, input, level, references);
        }
        return deferred(CERT_NO_KEY_RECORDED,
                "The certificate records no key it certifies, so its readiness cannot be affirmed",
                READS_FIELDS.get(CERT_NO_KEY_RECORDED), input, level, references);
    }

    private static PqcDecision protocol(PqcRuleInput input, Integer level, PqcReferences references) {
        List<PqcReferences.Reference> algorithms = references.suiteAlgorithms();
        Optional<PqcReferences.Reference> weakest = weakestResolved(algorithms);
        boolean unresolved = algorithms.stream().anyMatch(reference -> !reference.resolved());
        int unresolvedRank = unresolved ? UNRESOLVED_RANK : ABSENT_RANK;
        if (weakest.isPresent() && rank(weakest.get().targetVerdict()) <= unresolvedRank) {
            return resolved(PROTOCOL_CIPHER_SUITE,
                    "A protocol is as ready as the weakest algorithm its cipher suites " + "name", weakest.get(),
                    PROTOCOL_RESOLVED_FIELDS, input, level, references);
        }
        if (unresolved) {
            return deferred(PROTOCOL_SUITE_UNRESOLVED,
                    "A cipher suite names an algorithm that resolved to no evaluated inventory asset, so the "
                            + "protocol's readiness cannot be affirmed",
                    PROTOCOL_UNRESOLVED_FIELDS, input, level, references);
        }
        return deferred(PROTOCOL_NO_SUITES,
                "The protocol records no cipher suite that names an algorithm, so its readiness cannot be affirmed",
                READS_FIELDS.get(PROTOCOL_NO_SUITES), input, level, references);
    }

    /** The first reference, in suite order, that attains the weakest resolved verdict. */
    private static Optional<PqcReferences.Reference> weakestResolved(List<PqcReferences.Reference> references) {
        return references
                .stream()
                .filter(PqcReferences.Reference::resolved)
                .min(Comparator.comparingInt(reference -> rank(reference.targetVerdict())));
    }

    /** Why a reference rule before the deciding one did not decide, in terms of this asset's references. */
    static String notMatched(String ruleId, PqcReferences references) {
        Contribution key = Contribution.of(references.subjectKeys());
        Contribution signature = Contribution.of(references.signatureAlgorithms());
        return switch (ruleId) {
            case CERT_SUBJECT_KEY -> key.recorded()
                    ? key.resolved == null
                            ? "The certified key resolved to no evaluated inventory asset"
                            : "The signature algorithm is weaker than the certified key"
                    : "No certified key is recorded";
            case CERT_SIGNATURE_ALGORITHM -> signature.recorded()
                    ? signature.resolved == null
                            ? "The signature algorithm resolved to no evaluated inventory asset"
                            : "The signature algorithm is not weaker than the certified key"
                    : "No signature algorithm is recorded";
            case CERT_REFERENCE_UNRESOLVED -> "Every recorded reference resolved";
            case PROTOCOL_CIPHER_SUITE -> weakestResolved(references.suiteAlgorithms()).isEmpty()
                    ? "No cipher suite algorithm resolved to an evaluated inventory asset"
                    : "An unresolved cipher suite algorithm may be weaker than every resolved one";
            case PROTOCOL_SUITE_UNRESOLVED -> "Every cipher suite algorithm resolved";
            default -> throw new IllegalStateException("Rule " + ruleId + " is a catch-all and always matches");
        };
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

    private static int rank(PqcVerdict verdict) {
        return switch (verdict) {
            case NOT_READY -> 0;
            case UNKNOWN, NOT_APPLICABLE -> 1;
            case READY -> 2;
        };
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

        /**
         * What the key is weighed against: an absent signature algorithm adds nothing, an unresolved one may be weak.
         */
        int rankAgainstKey() {
            if (resolved != null) {
                return rank(resolved.targetVerdict());
            }
            return unresolved ? UNRESOLVED_RANK : ABSENT_RANK;
        }

        /** What the signature algorithm is weighed against: an absent or unresolved key may be weak. */
        int rankAgainstSignature() {
            return resolved != null ? rank(resolved.targetVerdict()) : UNRESOLVED_RANK;
        }
    }
}
