package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import java.util.List;
import java.util.Set;

/**
 * Every rule id the evaluator can decide by, in the order it consults them, with the title an explanation shows.
 *
 * <p>
 * The evaluator is a rule table followed by coded paths that emit ids the table does not hold; this list is the one
 * place both appear together. An explanation serves the entries that apply to the asset's type, so a certificate is not
 * shown twenty algorithm rules it was never tested against.
 *
 * <p>
 * The hybrid path composes its id from the deciding component ({@code PQC-HYBRID-PQC-STANDARDIZED}); those ids map to
 * the one {@code PQC-HYBRID} entry. {@code EVALUATION-FAILED} is a sweep stamp, not a rule, and has no entry.
 */
public final class PqcRuleCatalog {

    private static final Set<CryptographicAssetType> ALGORITHM_AND_MATERIAL = Set
            .of(CryptographicAssetType.ALGORITHM, CryptographicAssetType.RELATED_CRYPTO_MATERIAL);

    private static final Set<CryptographicAssetType> ALGORITHM = Set.of(CryptographicAssetType.ALGORITHM);

    private static final Set<CryptographicAssetType> MATERIAL = Set.of(CryptographicAssetType.RELATED_CRYPTO_MATERIAL);

    private static final Set<CryptographicAssetType> CERTIFICATE = Set.of(CryptographicAssetType.CERTIFICATE);

    private static final Set<CryptographicAssetType> PROTOCOL = Set.of(CryptographicAssetType.PROTOCOL);

    private static final List<String> FAMILY_FIELDS = List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT);

    private static final List<String> SIZE_FIELDS = List
            .of(PqcRules.ALGORITHM_FAMILY, PqcRules.PARAMETER_SET, PqcRules.MATERIAL_SIZE, PqcRules.VARIANT);

    private static final String HYBRID_PREFIX = PqcRules.HYBRID + "-";

    /**
     * @param readsFields what a not-matched step shows; {@code null} for a table or reference rule, whose declared
     * fields the evaluator already holds
     */
    public record Entry(String id, String title, Set<CryptographicAssetType> appliesTo, List<String> readsFields) {
    }

    private static final List<Entry> ENTRIES = List
            .of(new Entry(PqcReferenceRules.CERT_SUBJECT_KEY, "Certified key", CERTIFICATE, null),
                    new Entry(PqcReferenceRules.CERT_SIGNATURE_ALGORITHM, "Signature algorithm", CERTIFICATE, null),
                    new Entry(PqcReferenceRules.CERT_REFERENCE_UNRESOLVED, "Unresolved certificate reference",
                            CERTIFICATE, null),
                    new Entry(PqcReferenceRules.CERT_NO_SIGNATURE_RECORDED, "No signature algorithm recorded",
                            CERTIFICATE, null),
                    new Entry(PqcReferenceRules.CERT_NO_KEY_RECORDED, "No certified key recorded", CERTIFICATE, null),
                    new Entry(PqcReferenceRules.PROTOCOL_CIPHER_SUITE, "Cipher suite algorithms", PROTOCOL, null),
                    new Entry(PqcReferenceRules.PROTOCOL_SUITE_UNRESOLVED, "Unresolved cipher suite algorithm",
                            PROTOCOL, null),
                    new Entry(PqcReferenceRules.PROTOCOL_NO_KEY_EXCHANGE, "No key exchange named", PROTOCOL, null),
                    new Entry(PqcReferenceRules.PROTOCOL_NO_SUITES, "No cipher suites recorded", PROTOCOL, null),
                    new Entry("ASSET-TYPE-UNROUTABLE", "Asset type", Set.of(CryptographicAssetType.UNROUTABLE), null),
                    new Entry("MATERIAL-NOT-KEY", "Material that is not a key", MATERIAL, null),
                    new Entry("NAME-CIPHER-SUITE", "Cipher suite name", ALGORITHM, null),
                    new Entry("NAME-NOT-AN-ALGORITHM", "Non-algorithm name", ALGORITHM, null),
                    new Entry("MATERIAL-SYMMETRIC-READY", "Symmetric key size", MATERIAL, null),
                    new Entry("MATERIAL-SYMMETRIC-WEAK", "Undersized symmetric key", MATERIAL, null),
                    new Entry("MATERIAL-SYMMETRIC-UNSIZED", "Unsized symmetric key", MATERIAL, null),
                    new Entry("CLASSICAL-LEGACY-COMPONENT", "Classically broken component", ALGORITHM_AND_MATERIAL,
                            List
                                    .of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.VARIANT,
                                            PqcRules.NAME)),
                    new Entry(PqcRules.HYBRID, "Hybrid construction", ALGORITHM_AND_MATERIAL,
                            List
                                    .of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.NAME,
                                            PqcRules.VARIANT)),
                    new Entry("PQC-HYBRID-UNRESOLVED", "Hybrid without a ratified post-quantum component",
                            ALGORITHM_AND_MATERIAL,
                            List
                                    .of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.NAME,
                                            PqcRules.VARIANT)),
                    new Entry("CLASSICAL-SHOR-COMPONENT", "Quantum-vulnerable component", ALGORITHM_AND_MATERIAL,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT, PqcRules.NAME)),
                    new Entry(PqcRules.FAMILY_UNRESOLVED, "Unresolved algorithm family", ALGORITHM_AND_MATERIAL,
                            List
                                    .of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.ALGORITHM_FAMILY,
                                            PqcRules.NAME, PqcRules.VARIANT)),
                    new Entry(FamilyClass.SHOR_BREAKABLE.ruleId(), "Quantum-vulnerable family", ALGORITHM_AND_MATERIAL,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.CURVE, PqcRules.VARIANT)),
                    new Entry("FAMILY-AMBIGUOUS-COMPONENT", "Ambiguous primitive", ALGORITHM_AND_MATERIAL,
                            FAMILY_FIELDS),
                    new Entry("CONSTRUCTION-UNINSTANTIATED", "Construction without a primitive", ALGORITHM_AND_MATERIAL,
                            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT, PqcRules.PARAMETER_SET)),
                    new Entry("SYMMETRIC-UNDERSIZED", "Undersized symmetric primitive", ALGORITHM_AND_MATERIAL,
                            SIZE_FIELDS),
                    new Entry(FamilyClass.QUANTUM_RESISTANT_SYMMETRIC.ruleId(), "Symmetric or hash-based family",
                            ALGORITHM_AND_MATERIAL, SIZE_FIELDS),
                    new Entry("PQC-ONE-TIME-SIGNATURE", "One-time signature", ALGORITHM_AND_MATERIAL, FAMILY_FIELDS),
                    new Entry(FamilyClass.PQC_STANDARDIZED.ruleId(), "Standardised post-quantum scheme",
                            ALGORITHM_AND_MATERIAL, FAMILY_FIELDS),
                    new Entry(FamilyClass.PQC_PRESTANDARD.ruleId(), "Pre-standard post-quantum scheme",
                            ALGORITHM_AND_MATERIAL, FAMILY_FIELDS),
                    new Entry(FamilyClass.PQC_BROKEN.ruleId(), "Broken post-quantum candidate", ALGORITHM_AND_MATERIAL,
                            FAMILY_FIELDS),
                    new Entry(FamilyClass.PQC_HYBRID.ruleId(), "Named hybrid family", ALGORITHM_AND_MATERIAL,
                            FAMILY_FIELDS),
                    new Entry(FamilyClass.CLASSICAL_LEGACY.ruleId(), "Classically broken family",
                            ALGORITHM_AND_MATERIAL, FAMILY_FIELDS),
                    new Entry(FamilyClass.FAMILY_AMBIGUOUS.ruleId(), "Ambiguous family", ALGORITHM_AND_MATERIAL,
                            FAMILY_FIELDS));

    private PqcRuleCatalog() {
    }

    public static List<Entry> entries() {
        return ENTRIES;
    }

    /** The entries an asset of this type is evaluated against, in evaluation order. A null type is unroutable. */
    public static List<Entry> servedFor(CryptographicAssetType assetType) {
        CryptographicAssetType routed = assetType == null ? CryptographicAssetType.UNROUTABLE : assetType;
        return ENTRIES.stream().filter(entry -> entry.appliesTo().contains(routed)).toList();
    }

    /** The catalogue id a decided rule id is listed under: itself, or the hybrid entry for a composed hybrid id. */
    public static String entryIdOf(String decidedRuleId) {
        boolean listed = ENTRIES.stream().anyMatch(entry -> entry.id().equals(decidedRuleId));
        return !listed && decidedRuleId.startsWith(HYBRID_PREFIX) ? PqcRules.HYBRID : decidedRuleId;
    }
}
