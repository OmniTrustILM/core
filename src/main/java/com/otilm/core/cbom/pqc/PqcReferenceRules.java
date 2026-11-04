package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * Keys, certificates and protocols, which carry no algorithm of their own: a key is as ready as the algorithm its CBOM
 * says it is for, a certificate as the weaker of the key it certifies and the algorithm it is signed with, a protocol
 * as the weakest of what it offers -- the algorithms its cipher suites name, the TLS groups and signature schemes they
 * offer, the algorithms it names at the protocol level and the IKEv2 key exchange methods it proposes.
 *
 * <p>
 * Each rule answers for itself and {@link PqcRuleOrder} picks the weakest: {@code notReady}, then {@code unknown}, then
 * {@code ready}, the key ahead of the signature at a tie. A reference that resolved to nothing, to an asset not yet
 * evaluated, or to one the question does not apply to, is a deferral under its own rule id: it may be the weak one, so
 * it outranks a resolved {@code ready} and yields to a resolved finding. Every certificate is signed, so one with no
 * signature algorithm recorded is not affirmed on its key alone, and a protocol is affirmed only once something it
 * offers establishes a key. A TLS group or signature scheme is a name rather than a component, so it is judged inline
 * by the algorithm rules, as an algorithm of that name would be.
 */
final class PqcReferenceRules {

    static final String CERT_SUBJECT_KEY = "CERT-SUBJECT-KEY";

    static final String CERT_SIGNATURE_ALGORITHM = "CERT-SIGNATURE-ALGORITHM";

    static final String CERT_REFERENCE_UNRESOLVED = "CERT-REFERENCE-UNRESOLVED";

    static final String CERT_NO_SIGNATURE_RECORDED = "CERT-NO-SIGNATURE-RECORDED";

    static final String CERT_NO_KEY_RECORDED = "CERT-NO-KEY-RECORDED";

    static final String MATERIAL_ALGORITHM = "MATERIAL-ALGORITHM";

    static final String MATERIAL_ALGORITHM_UNRESOLVED = "MATERIAL-ALGORITHM-UNRESOLVED";

    static final String MATERIAL_NO_ALGORITHM_RECORDED = "MATERIAL-NO-ALGORITHM-RECORDED";

    static final String PROTOCOL_CIPHER_SUITE = "PROTOCOL-CIPHER-SUITE";

    static final String PROTOCOL_TLS_GROUP = "PROTOCOL-TLS-GROUP";

    static final String PROTOCOL_TLS_SIGNATURE_SCHEME = "PROTOCOL-TLS-SIGNATURE-SCHEME";

    static final String PROTOCOL_ALGORITHM = "PROTOCOL-ALGORITHM";

    static final String PROTOCOL_KEY_EXCHANGE = "PROTOCOL-KEY-EXCHANGE";

    static final String PROTOCOL_SUITE_UNRESOLVED = "PROTOCOL-SUITE-UNRESOLVED";

    static final String PROTOCOL_REFERENCE_UNRESOLVED = "PROTOCOL-REFERENCE-UNRESOLVED";

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

    private static final List<String> MATERIAL_RESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.ALGORITHM_REF, PqcRules.REFERENCED_RULE_ID);

    private static final List<String> MATERIAL_UNRESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.ALGORITHM_REF, PqcRules.UNRESOLVED_REFS);

    private static final List<String> SUITE_RESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.CIPHER_SUITES, PqcRules.CIPHER_SUITE_ALGORITHM_REFS,
                    PqcRules.CIPHER_SUITE, PqcRules.CIPHER_SUITE_ALGORITHM_REF, PqcRules.REFERENCED_RULE_ID);

    private static final List<String> SUITE_UNRESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.CIPHER_SUITES, PqcRules.CIPHER_SUITE_ALGORITHM_REFS,
                    PqcRules.UNRESOLVED_REFS);

    private static final List<String> PROTOCOL_REFERENCE_UNRESOLVED_FIELDS = List
            .of(PqcRules.ASSET_TYPE, PqcRules.PROTOCOL_ALGORITHM_REFS, PqcRules.KEY_EXCHANGE_REFS,
                    PqcRules.UNRESOLVED_REFS);

    /** The fields each rule reads, which a not-matched step shows. */
    static final Map<String, List<String>> READS_FIELDS = Map
            .ofEntries(Map.entry(CERT_SUBJECT_KEY, CERTIFICATE_RESOLVED_FIELDS),
                    Map.entry(CERT_SIGNATURE_ALGORITHM, CERTIFICATE_RESOLVED_FIELDS),
                    Map.entry(CERT_REFERENCE_UNRESOLVED, CERTIFICATE_UNRESOLVED_FIELDS),
                    Map
                            .entry(CERT_NO_SIGNATURE_RECORDED,
                                    List.of(PqcRules.ASSET_TYPE, PqcRules.SUBJECT_PUBLIC_KEY_REF)),
                    Map.entry(CERT_NO_KEY_RECORDED, List.of(PqcRules.ASSET_TYPE, PqcRules.SIGNATURE_ALGORITHM_REF)),
                    Map.entry(MATERIAL_ALGORITHM, MATERIAL_RESOLVED_FIELDS),
                    Map.entry(MATERIAL_ALGORITHM_UNRESOLVED, MATERIAL_UNRESOLVED_FIELDS),
                    Map
                            .entry(MATERIAL_NO_ALGORITHM_RECORDED,
                                    List.of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.NAME)),
                    Map.entry(PROTOCOL_CIPHER_SUITE, SUITE_RESOLVED_FIELDS),
                    Map
                            .entry(PROTOCOL_TLS_GROUP,
                                    List
                                            .of(PqcRules.ASSET_TYPE, PqcRules.TLS_GROUPS, PqcRules.TLS_GROUP,
                                                    PqcRules.REFERENCED_RULE_ID)),
                    Map
                            .entry(PROTOCOL_TLS_SIGNATURE_SCHEME,
                                    List
                                            .of(PqcRules.ASSET_TYPE, PqcRules.TLS_SIGNATURE_SCHEMES,
                                                    PqcRules.TLS_SIGNATURE_SCHEME, PqcRules.REFERENCED_RULE_ID)),
                    Map
                            .entry(PROTOCOL_ALGORITHM,
                                    List
                                            .of(PqcRules.ASSET_TYPE, PqcRules.PROTOCOL_ALGORITHM_REFS,
                                                    PqcRules.PROTOCOL_ALGORITHM_REF, PqcRules.REFERENCED_RULE_ID)),
                    Map
                            .entry(PROTOCOL_KEY_EXCHANGE,
                                    List
                                            .of(PqcRules.ASSET_TYPE, PqcRules.KEY_EXCHANGE_REFS,
                                                    PqcRules.KEY_EXCHANGE_REF, PqcRules.REFERENCED_RULE_ID)),
                    Map.entry(PROTOCOL_SUITE_UNRESOLVED, SUITE_UNRESOLVED_FIELDS),
                    Map.entry(PROTOCOL_REFERENCE_UNRESOLVED, PROTOCOL_REFERENCE_UNRESOLVED_FIELDS),
                    Map
                            .entry(PROTOCOL_NO_KEY_EXCHANGE,
                                    List
                                            .of(PqcRules.ASSET_TYPE, PqcRules.CIPHER_SUITES,
                                                    PqcRules.CIPHER_SUITE_ALGORITHM_REFS, PqcRules.TLS_GROUPS,
                                                    PqcRules.PROTOCOL_ALGORITHM_REFS, PqcRules.KEY_EXCHANGE_REFS)),
                    Map.entry(PROTOCOL_NO_SUITES, List.of(PqcRules.ASSET_TYPE)));

    /** A name the document offers, judged inline as an algorithm of that name. */
    record Offered(String name, PqcDecision decision) {
    }

    /** The inline verdicts of the names a protocol's suites offer, which the evaluator computes. */
    record Inline(List<Offered> groups, List<Offered> schemes) {

        static final Inline NONE = new Inline(List.of(), List.of());
    }

    private PqcReferenceRules() {
    }

    /** Whether an asset of this type is decided, in whole or in part, by what it references. */
    static boolean references(CryptographicAssetType assetType) {
        return assetType == CryptographicAssetType.CERTIFICATE || assetType == CryptographicAssetType.PROTOCOL
                || assetType == CryptographicAssetType.RELATED_CRYPTO_MATERIAL;
    }

    static boolean handles(String ruleId) {
        return READS_FIELDS.containsKey(ruleId);
    }

    /** What one rule says about the asset's references, or {@code null} when its condition does not hold. */
    static PqcDecision candidate(String ruleId, PqcRuleInput input, Integer level, PqcReferences references,
            Inline inline) {
        return switch (input.assetType()) {
            case CERTIFICATE -> certificate(ruleId, input, level, references);
            case RELATED_CRYPTO_MATERIAL -> material(ruleId, input, level, references);
            default -> protocol(ruleId, input, level, references, inline);
        };
    }

    private static PqcDecision certificate(String ruleId, PqcRuleInput input, Integer level, PqcReferences references) {
        Contribution key = Contribution.of(references.subjectKeys(), PqcReferences.Reference::resolved);
        Contribution signature = Contribution.of(references.signatureAlgorithms(), PqcReferences.Reference::resolved);
        return switch (ruleId) {
            case CERT_SUBJECT_KEY -> key.resolved == null
                    ? null
                    : resolved(CERT_SUBJECT_KEY, "The certificate is as ready as the key it certifies", key.resolved,
                            input, level, references);
            case CERT_SIGNATURE_ALGORITHM -> signature.resolved == null
                    ? null
                    : resolved(CERT_SIGNATURE_ALGORITHM,
                            "The certificate is as ready as the algorithm it is signed with", signature.resolved, input,
                            level, references);
            case CERT_REFERENCE_UNRESOLVED ->
                !key.unresolved && !signature.unresolved
                        ? null
                        : deferred(CERT_REFERENCE_UNRESOLVED,
                                "The certificate names a key or signature algorithm that resolved to no evaluated "
                                        + "inventory asset, so its readiness cannot be affirmed",
                                input, level, references);
            case CERT_NO_SIGNATURE_RECORDED -> !key.recorded() || signature.recorded()
                    ? null
                    : deferred(CERT_NO_SIGNATURE_RECORDED,
                            "The certificate records no signature algorithm, which may be weaker than the key it "
                                    + "certifies, so its readiness cannot be affirmed",
                            input, level, references);
            case CERT_NO_KEY_RECORDED -> key.recorded()
                    ? null
                    : deferred(CERT_NO_KEY_RECORDED,
                            "The certificate records no key it certifies, so its readiness cannot be affirmed", input,
                            level, references);
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a certificate rule");
        };
    }

    /**
     * A key's reference must name an algorithm: a key that names another key would make a chain, and the one-hop
     * doctrine is what keeps two referrers from re-offering each other.
     */
    private static PqcDecision material(String ruleId, PqcRuleInput input, Integer level, PqcReferences references) {
        Contribution algorithm = Contribution
                .of(references.algorithms(), PqcReferences.Reference::resolvedToAnAlgorithm);
        return switch (ruleId) {
            case MATERIAL_ALGORITHM -> algorithm.resolved == null
                    ? null
                    : resolved(MATERIAL_ALGORITHM, "The key is as ready as the algorithm it is for", algorithm.resolved,
                            input, level, references);
            case MATERIAL_ALGORITHM_UNRESOLVED -> !algorithm.unresolved
                    ? null
                    : deferred(MATERIAL_ALGORITHM_UNRESOLVED,
                            "The CBOM names an algorithm for the key that resolved to no evaluated inventory "
                                    + "algorithm, so its readiness cannot be affirmed",
                            input, level, references);
            case MATERIAL_NO_ALGORITHM_RECORDED -> algorithm.recorded()
                    ? null
                    : deferred(MATERIAL_NO_ALGORITHM_RECORDED,
                            "The CBOM does not record the algorithm this key is for, so no rule can classify it", input,
                            level, references);
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a key rule");
        };
    }

    private static PqcDecision protocol(String ruleId, PqcRuleInput input, Integer level, PqcReferences references,
            Inline inline) {
        Offers offers = Offers.of(references, inline);
        return switch (ruleId) {
            case PROTOCOL_CIPHER_SUITE -> offers.suites
                    .weakest()
                    .map(deciding -> decided(PROTOCOL_CIPHER_SUITE,
                            "A protocol is as ready as the weakest algorithm its cipher suites name", deciding, input,
                            level, references))
                    .orElse(null);
            case PROTOCOL_TLS_GROUP -> offers.groups
                    .weakest()
                    .map(deciding -> decided(PROTOCOL_TLS_GROUP,
                            "A protocol is as ready as the weakest group it offers for key exchange", deciding, input,
                            level, references))
                    .orElse(null);
            case PROTOCOL_TLS_SIGNATURE_SCHEME -> offers.schemes
                    .weakest()
                    .map(deciding -> decided(PROTOCOL_TLS_SIGNATURE_SCHEME,
                            "A protocol is as ready as the weakest signature scheme it offers", deciding, input, level,
                            references))
                    .orElse(null);
            case PROTOCOL_ALGORITHM -> offers.algorithms
                    .weakest()
                    .map(deciding -> decided(PROTOCOL_ALGORITHM,
                            "A protocol is as ready as the weakest algorithm it names", deciding, input, level,
                            references))
                    .orElse(null);
            case PROTOCOL_KEY_EXCHANGE -> offers.keyExchanges
                    .weakest()
                    .map(deciding -> decided(PROTOCOL_KEY_EXCHANGE,
                            "A protocol is as ready as the weakest key exchange method it offers", deciding, input,
                            level, references))
                    .orElse(null);
            case PROTOCOL_SUITE_UNRESOLVED -> !offers.suites.unresolved
                    ? null
                    : deferred(PROTOCOL_SUITE_UNRESOLVED,
                            "A cipher suite names an algorithm that resolved to no evaluated inventory asset, so the "
                                    + "protocol's readiness cannot be affirmed",
                            input, level, references);
            case PROTOCOL_REFERENCE_UNRESOLVED -> !offers.algorithms.unresolved && !offers.keyExchanges.unresolved
                    ? null
                    : deferred(PROTOCOL_REFERENCE_UNRESOLVED,
                            "The protocol names an algorithm or key exchange method that resolved to no evaluated "
                                    + "inventory algorithm, so its readiness cannot be affirmed",
                            input, level, references);
            case PROTOCOL_NO_KEY_EXCHANGE -> !offers.everythingIsReady() || offers.establishesAKey()
                    ? null
                    : deferred(PROTOCOL_NO_KEY_EXCHANGE,
                            "Everything the protocol offers is ready, but nothing it records establishes a key, "
                                    + "which the protocol negotiates separately and may be vulnerable",
                            input, level, references);
            case PROTOCOL_NO_SUITES -> offers.recordsSomething()
                    ? null
                    : deferred(PROTOCOL_NO_SUITES,
                            "The protocol records no cipher suite, group, signature scheme or algorithm, so its "
                                    + "readiness cannot be affirmed",
                            input, level, references);
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a protocol rule");
        };
    }

    /** Why a rule's condition did not hold, in terms of this asset's references. */
    static String notMatched(String ruleId, PqcReferences references, Inline inline) {
        Contribution key = Contribution.of(references.subjectKeys(), PqcReferences.Reference::resolved);
        Contribution signature = Contribution.of(references.signatureAlgorithms(), PqcReferences.Reference::resolved);
        Contribution algorithm = Contribution
                .of(references.algorithms(), PqcReferences.Reference::resolvedToAnAlgorithm);
        Offers offers = Offers.of(references, inline);
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
            case MATERIAL_ALGORITHM -> algorithm.recorded()
                    ? "The algorithm the key is for resolved to no evaluated inventory algorithm"
                    : "No algorithm is recorded for the key";
            case MATERIAL_ALGORITHM_UNRESOLVED ->
                algorithm.recorded() ? "The recorded algorithm resolved" : "No algorithm is recorded for the key";
            case MATERIAL_NO_ALGORITHM_RECORDED -> "An algorithm is recorded for the key";
            case PROTOCOL_CIPHER_SUITE -> "No cipher suite algorithm resolved to an evaluated inventory asset";
            case PROTOCOL_TLS_GROUP -> "No TLS group is offered";
            case PROTOCOL_TLS_SIGNATURE_SCHEME -> "No TLS signature scheme is offered";
            case PROTOCOL_ALGORITHM -> offers.algorithms.recorded()
                    ? "No algorithm named at the protocol level resolved to an evaluated inventory algorithm"
                    : "No algorithm is named at the protocol level";
            case PROTOCOL_KEY_EXCHANGE -> offers.keyExchanges.recorded()
                    ? "No key exchange method resolved to an evaluated inventory algorithm"
                    : "No key exchange method is offered";
            case PROTOCOL_SUITE_UNRESOLVED -> "Every cipher suite algorithm resolved";
            case PROTOCOL_REFERENCE_UNRESOLVED -> "Every algorithm named at the protocol level resolved";
            case PROTOCOL_NO_KEY_EXCHANGE -> keyExchangeNotMatched(offers);
            case PROTOCOL_NO_SUITES -> "The protocol records something to evaluate";
            default -> throw new IllegalStateException("Rule " + ruleId + " is not a reference rule");
        };
    }

    private static String keyExchangeNotMatched(Offers offers) {
        if (!offers.recordsSomething()) {
            return "The protocol records nothing to evaluate";
        }
        if (offers.anyUnresolved()) {
            return "A reference resolved to nothing, so not everything offered is known to be ready";
        }
        return offers.everythingIsReady()
                ? "Something the protocol offers establishes a key"
                : "Something the protocol offers is not ready";
    }

    /** The reference-side inputs, in {@link PqcRules#INPUT_FIELDS} order; absent ones omitted. */
    static Map<String, Object> inputs(PqcReferences references) {
        Map<String, Object> inputs = new LinkedHashMap<>();
        for (String field : List
                .of(PqcRules.SUBJECT_PUBLIC_KEY_REF, PqcRules.SIGNATURE_ALGORITHM_REF, PqcRules.ALGORITHM_REF,
                        PqcRules.CIPHER_SUITES, PqcRules.CIPHER_SUITE_ALGORITHM_REFS, PqcRules.TLS_GROUPS,
                        PqcRules.TLS_SIGNATURE_SCHEMES, PqcRules.PROTOCOL_ALGORITHM_REFS, PqcRules.KEY_EXCHANGE_REFS,
                        PqcRules.UNRESOLVED_REFS)) {
            putIfPresent(inputs, field, valueOf(field, references, null));
        }
        return inputs;
    }

    static Map<String, Object> evidence(List<String> fields, PqcRuleInput input, Integer level,
            PqcReferences references, Deciding deciding) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        for (String field : fields) {
            if (!PqcRules.EVIDENCE_FIELDS.contains(field)) {
                throw new IllegalStateException(
                        "A reference rule declares an evaluated field outside the allowlist: " + field);
            }
            Object value = switch (field) {
                case PqcRules.ASSET_TYPE -> input.assetType().getCode();
                case PqcRules.MATERIAL_TYPE -> input.materialType();
                case PqcRules.NAME -> input.name();
                default -> valueOf(field, references, deciding);
            };
            putIfPresent(evidence, field, value);
        }
        if (level != null) {
            evidence.put(PqcRules.NIST_QUANTUM_SECURITY_LEVEL, level);
        }
        return evidence;
    }

    private static Object valueOf(String field, PqcReferences references, Deciding deciding) {
        return switch (field) {
            case PqcRules.SUBJECT_PUBLIC_KEY_REF -> oneOrMany(refs(references.subjectKeys()));
            case PqcRules.SIGNATURE_ALGORITHM_REF -> oneOrMany(refs(references.signatureAlgorithms()));
            case PqcRules.ALGORITHM_REF -> oneOrMany(refs(references.algorithms()));
            case PqcRules.CIPHER_SUITES -> references.cipherSuites();
            case PqcRules.CIPHER_SUITE_ALGORITHM_REFS -> refs(references.suiteAlgorithms());
            case PqcRules.TLS_GROUPS -> references.tlsGroups();
            case PqcRules.TLS_SIGNATURE_SCHEMES -> references.tlsSignatureSchemes();
            case PqcRules.PROTOCOL_ALGORITHM_REFS -> refs(references.protocolAlgorithms());
            case PqcRules.KEY_EXCHANGE_REFS -> refs(references.keyExchanges());
            case PqcRules.UNRESOLVED_REFS -> unresolvedRefs(references);
            case PqcRules.CIPHER_SUITE -> deciding == null ? null : deciding.suite();
            case PqcRules.CIPHER_SUITE_ALGORITHM_REF, PqcRules.PROTOCOL_ALGORITHM_REF, PqcRules.KEY_EXCHANGE_REF,
                    PqcRules.TLS_GROUP, PqcRules.TLS_SIGNATURE_SCHEME ->
                deciding == null ? null : deciding.name();
            case PqcRules.REFERENCED_RULE_ID -> deciding == null ? null : deciding.ruleId();
            default -> throw new IllegalStateException("Unhandled reference field: " + field);
        };
    }

    /** Every recorded reference that did not resolve; a protocol-level reference to a non-algorithm is not one. */
    private static List<String> unresolvedRefs(PqcReferences references) {
        List<String> unresolved = new ArrayList<>();
        Stream
                .of(references.subjectKeys(), references.signatureAlgorithms(), references.suiteAlgorithms())
                .flatMap(List::stream)
                .filter(reference -> !reference.resolved())
                .forEach(reference -> unresolved.add(reference.ref()));
        references
                .algorithms()
                .stream()
                .filter(reference -> !reference.resolvedToAnAlgorithm())
                .forEach(reference -> unresolved.add(reference.ref()));
        Stream
                .of(references.protocolAlgorithms(), references.keyExchanges())
                .flatMap(List::stream)
                .filter(reference -> !reference.resolvedToAnAlgorithm() && !namesANonAlgorithm(reference))
                .forEach(reference -> unresolved.add(reference.ref()));
        return unresolved;
    }

    /**
     * A protocol-level reference to a component that is not an algorithm -- the 1.6 {@code cryptoRefArray} names the
     * protocol's certificate too -- says nothing about the protocol's readiness and is neither resolved nor unresolved.
     */
    private static boolean namesANonAlgorithm(PqcReferences.Reference reference) {
        return reference.target() != null && reference.targetType() != null
                && reference.targetType() != CryptographicAssetType.ALGORITHM;
    }

    private static PqcDecision resolved(String ruleId, String reason, PqcReferences.Reference deciding,
            PqcRuleInput input, Integer level, PqcReferences references) {
        return decided(ruleId, reason, Deciding.of(deciding), input, level, references);
    }

    private static PqcDecision decided(String ruleId, String reason, Deciding deciding, PqcRuleInput input,
            Integer level, PqcReferences references) {
        return new PqcDecision(deciding.verdict(), ruleId, reason,
                evidence(READS_FIELDS.get(ruleId), input, level, references, deciding), deciding.target());
    }

    private static PqcDecision deferred(String ruleId, String reason, PqcRuleInput input, Integer level,
            PqcReferences references) {
        return new PqcDecision(PqcVerdict.UNKNOWN, ruleId, reason,
                evidence(READS_FIELDS.get(ruleId), input, level, references, null));
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
     * What a rule decided by: a resolved reference, or a name judged inline. The verdict and the rule id are the
     * target's stored ones for a reference and the inline decision's for a name; {@code target} is null for a name.
     */
    record Deciding(String name, String suite, UUID target, PqcVerdict verdict, String ruleId, String primitive) {

        static Deciding of(PqcReferences.Reference reference) {
            return new Deciding(reference.ref(), reference.suite(), reference.target(), reference.targetVerdict(),
                    reference.targetRuleId(), reference.targetPrimitive());
        }

        static Deciding of(Offered offered) {
            return new Deciding(offered.name(), null, null, offered.decision().verdict(), offered.decision().ruleId(),
                    null);
        }
    }

    /**
     * One kind of thing a protocol offers, as the rules read it: what decided, in document order, and whether something
     * recorded resolved to nothing.
     */
    private record Offer(List<Deciding> decided, boolean unresolved, boolean recorded) {

        private static final Offer NONE = new Offer(List.of(), false, false);

        static Offer ofReferences(List<PqcReferences.Reference> references, Predicate<PqcReferences.Reference> counts,
                Predicate<PqcReferences.Reference> resolved) {
            List<Deciding> decided = references.stream().filter(resolved).map(Deciding::of).toList();
            boolean unresolved = references.stream().anyMatch(counts.and(resolved.negate()));
            return new Offer(decided, unresolved, !decided.isEmpty() || unresolved);
        }

        static Offer ofNames(List<Offered> offered) {
            return offered.isEmpty() ? NONE : new Offer(offered.stream().map(Deciding::of).toList(), false, true);
        }

        /** The first, in document order, that attains the weakest verdict. */
        Optional<Deciding> weakest() {
            return decided.stream().min(Comparator.comparingInt(deciding -> PqcRuleOrder.rank(deciding.verdict())));
        }

        boolean establishesAKey() {
            return decided
                    .stream()
                    .anyMatch(deciding -> deciding.primitive() != null
                            && KEY_ESTABLISHMENT.contains(deciding.primitive()));
        }
    }

    /** Everything a protocol offers, by kind. */
    private record Offers(Offer suites, Offer groups, Offer schemes, Offer algorithms, Offer keyExchanges) {

        static Offers of(PqcReferences references, Inline inline) {
            return new Offers(Offer
                    .ofReferences(references.suiteAlgorithms(), reference -> true, PqcReferences.Reference::resolved),
                    Offer.ofNames(inline.groups()), Offer.ofNames(inline.schemes()),
                    Offer
                            .ofReferences(references.protocolAlgorithms(), reference -> !namesANonAlgorithm(reference),
                                    PqcReferences.Reference::resolvedToAnAlgorithm),
                    Offer
                            .ofReferences(references.keyExchanges(), reference -> !namesANonAlgorithm(reference),
                                    PqcReferences.Reference::resolvedToAnAlgorithm));
        }

        private Stream<Offer> all() {
            return Stream.of(suites, groups, schemes, algorithms, keyExchanges);
        }

        boolean recordsSomething() {
            return all().anyMatch(Offer::recorded);
        }

        boolean anyUnresolved() {
            return all().anyMatch(Offer::unresolved);
        }

        /** Something was offered, everything resolved, and the weakest of it is ready. */
        boolean everythingIsReady() {
            Optional<PqcVerdict> weakest = all()
                    .flatMap(offer -> offer.weakest().stream())
                    .map(Deciding::verdict)
                    .min(Comparator.comparingInt(PqcRuleOrder::rank));
            return weakest.isPresent() && weakest.get() == PqcVerdict.READY && !anyUnresolved();
        }

        /**
         * Any offered group or key exchange method is a key exchange; among the named algorithms only a key agreement
         * or a KEM is one. A TLS 1.3 suite names only its AEAD cipher and hash, so a protocol whose suites are all
         * ready says nothing yet about the harvest-now-decrypt-later risk the verdict exists for.
         */
        boolean establishesAKey() {
            return groups.recorded() || !keyExchanges.decided().isEmpty() || suites.establishesAKey()
                    || algorithms.establishesAKey();
        }
    }

    /**
     * One of a certificate's or a key's singular references. More than one of a kind is ambiguous, which the ingest
     * already resolved to nothing.
     *
     * @param resolved the reference that decides, or null
     * @param unresolved whether something was recorded that did not resolve
     */
    private record Contribution(PqcReferences.Reference resolved, boolean unresolved) {

        static Contribution of(List<PqcReferences.Reference> references, Predicate<PqcReferences.Reference> resolved) {
            if (references.size() == 1 && resolved.test(references.get(0))) {
                return new Contribution(references.get(0), false);
            }
            return new Contribution(null, !references.isEmpty());
        }

        boolean recorded() {
            return resolved != null || unresolved;
        }
    }
}
