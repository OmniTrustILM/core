package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import java.util.List;
import java.util.Set;

/**
 * Every rule id the evaluator can decide by, in catalogue order, with the title an explanation shows.
 *
 * <p>
 * Every entry that applies to an asset's type is evaluated; {@link PqcRuleOrder} selects the deciding one. The order of
 * this list is the tie-break between matched rules of equal rank, so it is part of the rule set: a protocol's cipher
 * suite rule is listed before its group rule, so a tie between two ready offers names the suite algorithm.
 *
 * <p>
 * The hybrid path composes its id from the deciding component ({@code PQC-HYBRID-PQC-STANDARDIZED}); those ids map to
 * the one {@code PQC-HYBRID} entry. {@code EVALUATION-FAILED} is a sweep stamp, not a rule, and has no entry.
 */
public final class PqcRuleCatalog {

    /** Where a rule stands in {@link PqcRuleOrder}. */
    public enum Tier {
        /** The asset is outside the readiness question; decides ahead of every finding. */
        EXCLUSION,
        /** A readiness finding; the weakest verdict decides, catalogue position breaks a tie. */
        FINDING,
        /** Decides only when nothing else matched. */
        FALLBACK
    }

    private static final Set<CryptographicAssetType> ALGORITHM = Set.of(CryptographicAssetType.ALGORITHM);

    private static final Set<CryptographicAssetType> MATERIAL = Set.of(CryptographicAssetType.RELATED_CRYPTO_MATERIAL);

    private static final Set<CryptographicAssetType> CERTIFICATE = Set.of(CryptographicAssetType.CERTIFICATE);

    private static final Set<CryptographicAssetType> PROTOCOL = Set.of(CryptographicAssetType.PROTOCOL);

    private static final List<String> FAMILY_FIELDS = List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT);

    private static final List<String> SIZE_FIELDS = List
            .of(PqcRules.ALGORITHM_FAMILY, PqcRules.PRIMITIVE, PqcRules.PARAMETER_SET, PqcRules.VARIANT);

    private static final List<String> HYBRID_FIELDS = List
            .of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.NAME, PqcRules.VARIANT);

    private static final String HYBRID_PREFIX = PqcRules.HYBRID + "-";

    /**
     * @param readsFields what a not-matched step shows; {@code null} for a table or reference rule, whose declared
     * fields the evaluator already holds
     */
    public record Entry(String id, String title, Set<CryptographicAssetType> appliesTo, List<String> readsFields,
            Tier tier) {
    }

    private static final List<Entry> ENTRIES = List
            .of(finding(PqcReferenceRules.CERT_SUBJECT_KEY, "Certified key", CERTIFICATE, null),
                    finding(PqcReferenceRules.CERT_SIGNATURE_ALGORITHM, "Signature algorithm", CERTIFICATE, null),
                    finding(PqcReferenceRules.CERT_REFERENCE_UNRESOLVED, "Unresolved certificate reference",
                            CERTIFICATE, null),
                    finding(PqcReferenceRules.CERT_NO_SIGNATURE_RECORDED, "No signature algorithm recorded",
                            CERTIFICATE, null),
                    finding(PqcReferenceRules.CERT_NO_KEY_RECORDED, "No certified key recorded", CERTIFICATE, null),
                    finding(PqcReferenceRules.PROTOCOL_CIPHER_SUITE, "Cipher suite algorithms", PROTOCOL, null),
                    finding(PqcReferenceRules.PROTOCOL_TLS_GROUP, "Offered TLS groups", PROTOCOL, null),
                    finding(PqcReferenceRules.PROTOCOL_TLS_SIGNATURE_SCHEME, "Offered TLS signature schemes", PROTOCOL,
                            null),
                    finding(PqcReferenceRules.PROTOCOL_ALGORITHM, "Protocol-level algorithms", PROTOCOL, null),
                    finding(PqcReferenceRules.PROTOCOL_KEY_EXCHANGE, "Key exchange methods", PROTOCOL, null),
                    finding(PqcReferenceRules.PROTOCOL_SUITE_UNRESOLVED, "Unresolved cipher suite algorithm", PROTOCOL,
                            null),
                    finding(PqcReferenceRules.PROTOCOL_REFERENCE_UNRESOLVED, "Unresolved protocol reference", PROTOCOL,
                            null),
                    finding(PqcReferenceRules.PROTOCOL_NO_KEY_EXCHANGE, "No key exchange named", PROTOCOL, null),
                    finding(PqcReferenceRules.PROTOCOL_NO_SUITES, "Nothing recorded to evaluate", PROTOCOL, null),
                    new Entry(PqcRules.MATERIAL_NOT_KEY, "Material that is not a key", MATERIAL, null, Tier.EXCLUSION),
                    new Entry(PqcRules.NAME_CIPHER_SUITE, "Cipher suite name", ALGORITHM, null, Tier.EXCLUSION),
                    new Entry(PqcRules.NAME_NOT_AN_ALGORITHM, "Non-algorithm name", ALGORITHM, null, Tier.EXCLUSION),
                    finding(PqcReferenceRules.MATERIAL_ALGORITHM, "Algorithm the key is for", MATERIAL, null),
                    finding(PqcReferenceRules.MATERIAL_ALGORITHM_UNRESOLVED, "Unresolved key algorithm", MATERIAL,
                            null),
                    finding(PqcRules.MATERIAL_SYMMETRIC_READY, "Symmetric key size", MATERIAL, null),
                    finding(PqcRules.MATERIAL_SYMMETRIC_WEAK, "Undersized symmetric key", MATERIAL, null),
                    finding(PqcRules.MATERIAL_SYMMETRIC_UNSIZED, "Unsized symmetric key", MATERIAL, null),
                    new Entry(PqcReferenceRules.MATERIAL_NO_ALGORITHM_RECORDED, "No key algorithm recorded", MATERIAL,
                            null, Tier.FALLBACK),
                    finding(PqcRules.CLASSICAL_LEGACY_COMPONENT, "Classically broken component", ALGORITHM,
                            HYBRID_FIELDS),
                    finding(PqcRules.HYBRID, "Hybrid construction", ALGORITHM, HYBRID_FIELDS),
                    finding(PqcRules.HYBRID_UNRESOLVED, "Hybrid without a ratified post-quantum component", ALGORITHM,
                            HYBRID_FIELDS),
                    finding(PqcRules.CLASSICAL_SHOR_COMPONENT, "Quantum-vulnerable component", ALGORITHM,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT, PqcRules.NAME)),
                    new Entry(PqcRules.FAMILY_UNRESOLVED, "Unresolved algorithm family", ALGORITHM,
                            List
                                    .of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.ALGORITHM_FAMILY,
                                            PqcRules.NAME, PqcRules.VARIANT),
                            Tier.FALLBACK),
                    finding(FamilyClass.SHOR_BREAKABLE.ruleId(), "Quantum-vulnerable family", ALGORITHM,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.CURVE, PqcRules.VARIANT)),
                    finding(PqcRules.FAMILY_AMBIGUOUS_COMPONENT, "Ambiguous primitive", ALGORITHM, FAMILY_FIELDS),
                    finding(PqcRules.CONSTRUCTION_UNINSTANTIATED, "Construction without a primitive", ALGORITHM,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT, PqcRules.PARAMETER_SET)),
                    finding(PqcRules.PARAMETER_SET_UNREGISTERED, "Parameter set the family does not define", ALGORITHM,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.PARAMETER_SET, PqcRules.VARIANT)),
                    finding(PqcRules.SYMMETRIC_UNDERSIZED, "Undersized symmetric primitive", ALGORITHM, SIZE_FIELDS),
                    finding(PqcRules.SYMMETRIC_UNSIZED, "Unsized symmetric primitive", ALGORITHM, SIZE_FIELDS),
                    finding(FamilyClass.QUANTUM_RESISTANT_SYMMETRIC.ruleId(), "Symmetric or hash-based family",
                            ALGORITHM, SIZE_FIELDS),
                    finding(PqcRules.ONE_TIME_SIGNATURE, "One-time signature", ALGORITHM, FAMILY_FIELDS),
                    finding(FamilyClass.PQC_STANDARDIZED.ruleId(), "Standardised post-quantum scheme", ALGORITHM,
                            FAMILY_FIELDS),
                    finding(FamilyClass.PQC_PRESTANDARD.ruleId(), "Pre-standard post-quantum scheme", ALGORITHM,
                            FAMILY_FIELDS),
                    finding(FamilyClass.PQC_BROKEN.ruleId(), "Broken post-quantum candidate", ALGORITHM, FAMILY_FIELDS),
                    finding(FamilyClass.PQC_HYBRID.ruleId(), "Named hybrid family", ALGORITHM, FAMILY_FIELDS),
                    finding(FamilyClass.CLASSICAL_LEGACY.ruleId(), "Classically broken family", ALGORITHM,
                            FAMILY_FIELDS),
                    finding(FamilyClass.FAMILY_AMBIGUOUS.ruleId(), "Ambiguous family", ALGORITHM, FAMILY_FIELDS));

    private PqcRuleCatalog() {
    }

    private static Entry finding(String id, String title, Set<CryptographicAssetType> appliesTo,
            List<String> readsFields) {
        return new Entry(id, title, appliesTo, readsFields, Tier.FINDING);
    }

    public static List<Entry> entries() {
        return ENTRIES;
    }

    /**
     * The entries an asset of this type is evaluated against, in catalogue order. Empty for a type no rule applies to:
     * the unroutable tier is no longer inventoried, so a row still carrying it cannot be evaluated.
     */
    public static List<Entry> servedFor(CryptographicAssetType assetType) {
        return assetType == null
                ? List.of()
                : ENTRIES.stream().filter(entry -> entry.appliesTo().contains(assetType)).toList();
    }

    /** The catalogue id a decided rule id is listed under: itself, or the hybrid entry for a composed hybrid id. */
    public static String entryIdOf(String decidedRuleId) {
        boolean listed = ENTRIES.stream().anyMatch(entry -> entry.id().equals(decidedRuleId));
        return !listed && decidedRuleId.startsWith(HYBRID_PREFIX) ? PqcRules.HYBRID : decidedRuleId;
    }
}
