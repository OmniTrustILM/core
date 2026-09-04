package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.List;
import java.util.Set;

/**
 * The hardcoded rule set: first match wins, and the last rule matches everything.
 *
 * <p>
 * <b>Deliberately non-configurable.</b> No YAML, no {@code @Value}, no Settings entry. "Which families are ready" is a
 * cryptographic fact the platform ships an opinion about, not an operator's risk appetite, and a per-tenant rule set
 * would make one deployment's verdict distribution incomparable with another's. What an operator can change is when the
 * re-evaluation sweep runs, which is a mechanic and lives on the scheduled job.
 *
 * <p>
 * <b>Order carries meaning, and two orderings are load-bearing.</b> The hybrid rule runs before every family rule: a
 * hybrid's stored family is whichever construction the identity grammar elected, so {@code X25519-ML-KEM-768} stores
 * the classical half and a family-first order would report a migrated asset as un-migrated. And the asset-type rules
 * run before everything: an asset that is not an algorithm has no family to read, and letting it fall through would
 * score every certificate as an unclassifiable miss.
 */
public final class PqcRules {

    /**
     * The closed set of names {@code pqc_evaluated_fields} may carry.
     *
     * <p>
     * This is the write-side half of the identity-key constraint. The column is served verbatim to clients as
     * {@code CryptographicAssetVerdictDto.evaluatedFields}, and {@code IdentityKeyExposureFence} cannot see into it --
     * it is lexical over source text, and both ends of the channel are innocuously named. So the guarantee is that
     * nothing else can be written: every rule declares its inputs, every declared name is checked against this set at
     * class-init, and the evidence map is projected rather than collected. {@link PqcRuleInput} carries no identity
     * key, canonical key or absorbed key to begin with, which is what makes the guarantee structural instead of a
     * filter someone has to remember to update.
     */
    public static final Set<String> EVIDENCE_FIELDS = Set
            .of("assetType", "algorithmFamily", "parameterSet", "curve", "mode", "padding", "variant", "name",
                    "hybridComponents", "materialType", "materialSize", "nistQuantumSecurityLevel");

    /** Material that is one half of a key pair: its family decides it, exactly as an algorithm's would. */
    public static final Set<String> ASYMMETRIC_MATERIAL = Set.of("private-key", "public-key", "key-pair");

    /** Material that is a symmetric key or a shared secret: quantum-resistant if it is long enough. */
    public static final Set<String> SYMMETRIC_MATERIAL = Set.of("secret-key", "symmetric-key", "shared-secret");

    /**
     * Material that is not a key at all, and so is outside the readiness question rather than unclassifiable within it.
     * {@code key} is here because the corpus spells keystore containers that way -- {@code truststore.p12},
     * {@code server-keystore.p12} -- and a container's readiness is the readiness of what it holds, which is its own
     * row.
     */
    public static final Set<String> NON_KEY_MATERIAL = Set
            .of("ciphertext", "signature", "digest", "initialization-vector", "nonce", "seed", "salt", "tag",
                    "additional-data", "password", "credential", "token", "other", "key");

    /**
     * The smallest symmetric key this rule set will call ready. Grover's algorithm halves the effective strength, so
     * 128 bits is the floor at which the halved strength still exceeds what is reachable.
     */
    public static final int MIN_SYMMETRIC_KEY_BITS = 128;

    public static final String FAMILY_UNRESOLVED = "FAMILY-UNRESOLVED";

    private PqcRules() {
    }

    private static final List<PqcRule> RULES = List
            .of(
                    // ---- Asset types that carry no algorithm of their own -------------------------------------
                    new PqcRule("CERT-DEFERRED-V1", input -> input.assetType() == CryptographicAssetType.CERTIFICATE,
                            PqcVerdict.NOT_APPLICABLE,
                            "A certificate's readiness is the readiness of the key it certifies, which this rule-set "
                                    + "generation does not resolve",
                            List.of("assetType")),
                    new PqcRule("PROTOCOL-NOT-ALGORITHM", input -> input.assetType() == CryptographicAssetType.PROTOCOL,
                            PqcVerdict.NOT_APPLICABLE,
                            "A protocol is not an algorithm; readiness belongs to the algorithms it negotiates",
                            List.of("assetType")),
                    new PqcRule("ASSET-TYPE-UNROUTABLE",
                            input -> input.assetType() == null
                                    || input.assetType() == CryptographicAssetType.UNROUTABLE,
                            PqcVerdict.NOT_APPLICABLE,
                            "The producer named an asset type this platform does not route, so there is no algorithm "
                                    + "to assess",
                            List.of("assetType")),

                    // ---- Material that is not a key -----------------------------------------------------------
                    new PqcRule("MATERIAL-NOT-KEY", input -> isMaterial(NON_KEY_MATERIAL, input),
                            PqcVerdict.NOT_APPLICABLE,
                            "This cryptographic material is not a key, so it is outside the readiness question",
                            List.of("assetType", "materialType")),

                    // ---- Names that are not algorithm names ---------------------------------------------------
                    new PqcRule("NAME-CIPHER-SUITE", PqcRules::isSuiteShapedName, PqcVerdict.NOT_APPLICABLE,
                            "The name denotes a cipher suite rather than a single algorithm; readiness belongs to its "
                                    + "component algorithms",
                            List.of("name")),

                    // ---- Hybrids, before any family rule ------------------------------------------------------
                    // No predicate of its own beyond being hybrid: the verdict is its post-quantum component's, so
                    // the evaluator resolves it rather than this table. See PqcEvaluator#hybridDecision.
                    new PqcRule("PQC-HYBRID", PqcRuleInput::isHybrid, PqcVerdict.READY,
                            "A hybrid construction; its readiness is that of its post-quantum component",
                            List.of("algorithmFamily", "hybridComponents", "name")),

                    // ---- Symmetric key material ---------------------------------------------------------------
                    new PqcRule("MATERIAL-SYMMETRIC-READY",
                            input -> isMaterial(SYMMETRIC_MATERIAL, input)
                                    && input.materialSize() != null && input.materialSize() >= MIN_SYMMETRIC_KEY_BITS,
                            PqcVerdict.READY,
                            "A symmetric key of at least 128 bits; Grover's algorithm halves its strength but does not "
                                    + "break it",
                            List.of("assetType", "materialType", "materialSize")),
                    new PqcRule("MATERIAL-SYMMETRIC-UNSIZED", input -> isMaterial(SYMMETRIC_MATERIAL, input),
                            PqcVerdict.UNKNOWN,
                            "A symmetric key whose declared size is absent or below 128 bits, so its strength cannot "
                                    + "be affirmed",
                            List.of("assetType", "materialType", "materialSize")));

    /**
     * The rules that run before the family table. The family table itself is not expressed as predicates -- it is a map
     * lookup in {@link PqcEvaluator}, because 130 one-family predicates would be a table written the slow way.
     */
    public static List<PqcRule> preFamilyRules() {
        return RULES;
    }

    /**
     * Suite-shaped names, detected without the identity grammar.
     *
     * <p>
     * {@code AssetNormalizer.isCipherSuiteName} is the ratified detector and the evaluator prefers it; this is the
     * fallback for the stored-row shape, where the name is already folded. The overlap with core#2196's ruling C8 --
     * which leaves open what an algorithm row keys as once a suite-shaped name stops electing a family -- is deliberate
     * and harmless: a suite name is not a single algorithm whichever family it elects or fails to elect, so this
     * verdict does not depend on how that ruling resolves.
     */
    /**
     * Whether the material type is one of {@code types}.
     *
     * <p>
     * The null guard is not defensive noise: most assets are algorithms and carry no material type at all, and
     * {@code Set.of(...)} throws {@link NullPointerException} on a null lookup rather than answering false -- so the
     * unguarded form failed on every algorithm in the inventory, which is to say on half of it.
     */
    static boolean isMaterial(Set<String> types, PqcRuleInput input) {
        return input.materialType() != null && types.contains(input.materialType());
    }

    static boolean isSuiteShapedName(PqcRuleInput input) {
        String name = input.name();
        if (name == null) {
            return false;
        }
        String upper = name.toUpperCase(java.util.Locale.ROOT);
        return upper.startsWith("TLS_") || upper.startsWith("SSL_") || upper.startsWith("TLS-")
                || upper.contains("_WITH_");
    }
}
