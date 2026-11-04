package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The rule ids, the evidence vocabulary, and the table half of the rule set: the exclusions and the material size arms.
 * The family, component and hybrid rules are coded in {@link PqcEvaluator}, because their ids and reasons are computed.
 *
 * <p>
 * Every rule is evaluated and {@link PqcRuleOrder} selects the deciding one, so no rule's answer depends on where it is
 * listed; the catalogue position only breaks a tie between rules of equal rank.
 *
 * <p>
 * Deliberately non-configurable: which families are ready is a fact the platform ships an opinion about, and a
 * per-tenant rule set would make two deployments' verdict distributions incomparable.
 */
public final class PqcRules {

    /**
     * The closed set {@code pqc_evaluated_fields} may carry. The write-side half of the identity-key constraint: the
     * column is served verbatim and {@code IdentityKeyExposureFence} cannot see into it, so what guarantees the key
     * stays out is that {@link PqcRuleInput} never holds one and nothing else can be written.
     */
    public static final String ASSET_TYPE = "assetType";

    public static final String ALGORITHM_FAMILY = "algorithmFamily";

    public static final String PRIMITIVE = "primitive";

    public static final String PARAMETER_SET = "parameterSet";

    public static final String CURVE = "curve";

    public static final String VARIANT = "variant";

    public static final String NAME = "name";

    public static final String HYBRID_COMPONENTS = "hybridComponents";

    public static final String MATERIAL_TYPE = "materialType";

    public static final String MATERIAL_SIZE = "materialSize";

    public static final String NIST_QUANTUM_SECURITY_LEVEL = "nistQuantumSecurityLevel";

    /** A certificate's, a key's and a protocol's references, as the bom-refs the document recorded. */
    public static final String SUBJECT_PUBLIC_KEY_REF = "subjectPublicKeyRef";

    public static final String SIGNATURE_ALGORITHM_REF = "signatureAlgorithmRef";

    public static final String ALGORITHM_REF = "algorithmRef";

    public static final String CIPHER_SUITES = "cipherSuites";

    public static final String CIPHER_SUITE_ALGORITHM_REFS = "cipherSuiteAlgorithmRefs";

    public static final String PROTOCOL_ALGORITHM_REFS = "protocolAlgorithmRefs";

    public static final String KEY_EXCHANGE_REFS = "keyExchangeRefs";

    /** The names a protocol's suites offer, which the rules judge inline rather than resolve. */
    public static final String TLS_GROUPS = "tlsGroups";

    public static final String TLS_SIGNATURE_SCHEMES = "tlsSignatureSchemes";

    public static final String UNRESOLVED_REFS = "unresolvedRefs";

    /** What a resolved reference rule decided by. Evidence of a decision, never an input. */
    public static final String CIPHER_SUITE = "cipherSuite";

    public static final String CIPHER_SUITE_ALGORITHM_REF = "cipherSuiteAlgorithmRef";

    public static final String PROTOCOL_ALGORITHM_REF = "protocolAlgorithmRef";

    public static final String KEY_EXCHANGE_REF = "keyExchangeRef";

    public static final String TLS_GROUP = "tlsGroup";

    public static final String TLS_SIGNATURE_SCHEME = "tlsSignatureScheme";

    public static final String REFERENCED_RULE_ID = "referencedRuleId";

    /**
     * The evidence values copied verbatim from the electing CBOM document -- its bom-refs, suite labels and offered
     * names -- which a caller who may not read that document must not be served, as the elected payload itself is not.
     */
    public static final Set<String> DOCUMENT_FIELDS = Set
            .of(SUBJECT_PUBLIC_KEY_REF, SIGNATURE_ALGORITHM_REF, ALGORITHM_REF, CIPHER_SUITES,
                    CIPHER_SUITE_ALGORITHM_REFS, PROTOCOL_ALGORITHM_REFS, KEY_EXCHANGE_REFS, TLS_GROUPS,
                    TLS_SIGNATURE_SCHEMES, UNRESOLVED_REFS, CIPHER_SUITE, CIPHER_SUITE_ALGORITHM_REF,
                    PROTOCOL_ALGORITHM_REF, KEY_EXCHANGE_REF, TLS_GROUP, TLS_SIGNATURE_SCHEME);

    /** What the rules read, in the order an explanation serves them as its inputs. */
    public static final List<String> INPUT_FIELDS = List
            .of(ASSET_TYPE, ALGORITHM_FAMILY, PRIMITIVE, PARAMETER_SET, CURVE, "mode", "padding", VARIANT, NAME,
                    HYBRID_COMPONENTS, MATERIAL_TYPE, MATERIAL_SIZE, NIST_QUANTUM_SECURITY_LEVEL,
                    SUBJECT_PUBLIC_KEY_REF, SIGNATURE_ALGORITHM_REF, ALGORITHM_REF, CIPHER_SUITES,
                    CIPHER_SUITE_ALGORITHM_REFS, TLS_GROUPS, TLS_SIGNATURE_SCHEMES, PROTOCOL_ALGORITHM_REFS,
                    KEY_EXCHANGE_REFS, UNRESOLVED_REFS);

    public static final Set<String> EVIDENCE_FIELDS = Set
            .copyOf(Stream
                    .concat(INPUT_FIELDS.stream(),
                            Stream
                                    .of(CIPHER_SUITE, CIPHER_SUITE_ALGORITHM_REF, PROTOCOL_ALGORITHM_REF,
                                            KEY_EXCHANGE_REF, TLS_GROUP, TLS_SIGNATURE_SCHEME, REFERENCED_RULE_ID))
                    .toList());

    /** Symmetric key or shared secret: quantum-resistant if long enough. */
    public static final Set<String> SYMMETRIC_MATERIAL = Set.of("secret-key", "symmetric-key", "shared-secret");

    /**
     * Not a key, so outside the question rather than unclassifiable within it.
     *
     * <p>
     * {@code key} and {@code other} are deliberately absent. CycloneDX defines {@code key} as material that processes
     * cryptographic data -- it is a key, and the corpus holds an {@code RSA-2048 Private Key} typed that way beside the
     * keystore containers. Calling those not-applicable answered "outside the question" for a private key. They fall to
     * the family rules instead, and to {@code unknown} when no family resolves, which is the honest answer.
     */
    public static final Set<String> NON_KEY_MATERIAL = Set
            .of("ciphertext", "signature", "digest", "initialization-vector", "nonce", "seed", "salt", "tag",
                    "additional-data", "password", "credential", "token");

    /**
     * The symmetric floor: CNSA 2.0 admits AES-256 and nothing smaller, and the same floor holds for every recorded
     * size the symmetric and hash-based rules read -- a digest length included -- so there is one number to state.
     */
    public static final int MIN_SYMMETRIC_KEY_BITS = 256;

    /**
     * The CycloneDX primitives whose parameter set is an output or tag length rather than a key size, so no key-size
     * rule reads it.
     */
    public static final Set<String> NON_KEY_PRIMITIVES = Set.of("kdf", "drbg", "mac", "xof");

    public static final String MATERIAL_NOT_KEY = "MATERIAL-NOT-KEY";

    public static final String NAME_CIPHER_SUITE = "NAME-CIPHER-SUITE";

    public static final String NAME_NOT_AN_ALGORITHM = "NAME-NOT-AN-ALGORITHM";

    public static final String MATERIAL_SYMMETRIC_READY = "MATERIAL-SYMMETRIC-READY";

    public static final String MATERIAL_SYMMETRIC_WEAK = "MATERIAL-SYMMETRIC-WEAK";

    public static final String MATERIAL_SYMMETRIC_UNSIZED = "MATERIAL-SYMMETRIC-UNSIZED";

    public static final String FAMILY_UNRESOLVED = "FAMILY-UNRESOLVED";

    public static final String HYBRID = "PQC-HYBRID";

    public static final String HYBRID_UNRESOLVED = "PQC-HYBRID-UNRESOLVED";

    /** Appended to a family disposition's rule id when a component, not the family, decides. */
    public static final String COMPONENT_RULE_SUFFIX = "-COMPONENT";

    public static final String CLASSICAL_LEGACY_COMPONENT = FamilyClass.CLASSICAL_LEGACY.ruleId()
            + COMPONENT_RULE_SUFFIX;

    public static final String CLASSICAL_SHOR_COMPONENT = FamilyClass.SHOR_BREAKABLE.ruleId() + COMPONENT_RULE_SUFFIX;

    public static final String FAMILY_AMBIGUOUS_COMPONENT = FamilyClass.FAMILY_AMBIGUOUS.ruleId()
            + COMPONENT_RULE_SUFFIX;

    public static final String CONSTRUCTION_UNINSTANTIATED = "CONSTRUCTION-UNINSTANTIATED";

    public static final String PARAMETER_SET_UNREGISTERED = "PARAMETER-SET-UNREGISTERED";

    public static final String SYMMETRIC_UNDERSIZED = "SYMMETRIC-UNDERSIZED";

    public static final String SYMMETRIC_UNSIZED = "SYMMETRIC-UNSIZED";

    public static final String ONE_TIME_SIGNATURE = "PQC-ONE-TIME-SIGNATURE";

    /** Stamped on a row the rules threw on. Not a rule, so it has no catalogue entry. */
    public static final String EVALUATION_FAILED = "EVALUATION-FAILED";

    public static final String EVALUATION_FAILED_REASON = "The rule set could not be evaluated against this asset's "
            + "recorded properties";

    private static final List<String> SYMMETRIC_MATERIAL_FIELDS = List
            .of(ASSET_TYPE, MATERIAL_TYPE, MATERIAL_SIZE, NAME);

    private PqcRules() {
    }

    /**
     * The symmetric size arms read the key's declared size alone. Its name is not evidence: a key is named after what
     * it protects, and the algorithm it is for is the reference {@link PqcReferenceRules} reads, which decides beside
     * these arms and outranks them when weaker.
     */
    static List<PqcRule> rulesFor(AssetNormalizer normalizer) {
        return List
                .of(
                        // ---- Material that is not a key -----------------------------------------------------------
                        new PqcRule(MATERIAL_NOT_KEY, input -> isMaterial(NON_KEY_MATERIAL, input),
                                PqcVerdict.NOT_APPLICABLE,
                                "This cryptographic material is not a key, so it is outside the readiness question",
                                List.of(ASSET_TYPE, MATERIAL_TYPE)),

                        // ---- Names that are not algorithm names ---------------------------------------------------
                        // Both yield to a resolved family: a producer that declares `RSA` on an asset it named `digest`
                        // has said what the asset is, and a 56-entry name list must not remove it from the inventory.
                        new PqcRule(NAME_CIPHER_SUITE,
                                input -> input.assetType() == CryptographicAssetType.ALGORITHM
                                        && PqcFamilies.of(input.algorithmFamily()) == null && input.name() != null
                                        && normalizer.isCipherSuiteName(input.name()),
                                PqcVerdict.NOT_APPLICABLE,
                                "The name denotes a cipher suite rather than a single algorithm; readiness belongs to its "
                                        + "component algorithms",
                                List.of(ASSET_TYPE, ALGORITHM_FAMILY, NAME)),
                        new PqcRule(NAME_NOT_AN_ALGORITHM,
                                input -> input.assetType() == CryptographicAssetType.ALGORITHM
                                        && PqcFamilies.of(input.algorithmFamily()) == null && isNonAlgorithmName(input),
                                PqcVerdict.NOT_APPLICABLE,
                                "The name denotes a library, an API, a container format or a construction category rather "
                                        + "than an algorithm",
                                List.of(ASSET_TYPE, ALGORITHM_FAMILY, NAME)),

                        // ---- Symmetric key material ---------------------------------------------------------------
                        // Below 64 a bit count cannot be told from a byte count -- 32 is either AES-256 in bytes or a
                        // broken key in bits -- so such a size reads as absent rather than as a strength.
                        new PqcRule(MATERIAL_SYMMETRIC_READY,
                                input -> isMaterial(SYMMETRIC_MATERIAL, input) && input.materialSize() != null
                                        && input.materialSize() >= MIN_SYMMETRIC_KEY_BITS,
                                PqcVerdict.READY,
                                "A symmetric key of at least " + MIN_SYMMETRIC_KEY_BITS
                                        + " bits; Grover's algorithm halves its strength but does not break it",
                                SYMMETRIC_MATERIAL_FIELDS),
                        new PqcRule(MATERIAL_SYMMETRIC_WEAK,
                                input -> isMaterial(SYMMETRIC_MATERIAL, input) && input.materialSize() != null
                                        && input.materialSize() < MIN_SYMMETRIC_KEY_BITS,
                                PqcVerdict.NOT_READY,
                                "A symmetric key whose declared size is below the " + MIN_SYMMETRIC_KEY_BITS
                                        + "-bit floor this rule set holds symmetric keys to",
                                SYMMETRIC_MATERIAL_FIELDS),
                        new PqcRule(MATERIAL_SYMMETRIC_UNSIZED,
                                input -> isMaterial(SYMMETRIC_MATERIAL, input) && input.materialSize() == null,
                                PqcVerdict.UNKNOWN,
                                "A symmetric key whose declared size is absent or implausible, so its strength cannot "
                                        + "be affirmed",
                                SYMMETRIC_MATERIAL_FIELDS));
    }

    /**
     * The asset-type gate is not redundant: a producer bug stamps {@code relatedCryptoMaterialProperties} onto
     * algorithms, {@code MaterialRedaction} keeps the block whatever the type, and without the gate an algorithm row
     * carrying a stray {@code salt} read {@code notApplicable} instead of {@code notReady}.
     */
    static boolean isNonAlgorithmName(PqcRuleInput input) {
        if (input.name() == null) {
            return false;
        }
        String folded = input.name().trim().toLowerCase(Locale.ROOT);
        return NON_ALGORITHM_NAMES.contains(folded);
    }

    private static final Set<String> NON_ALGORITHM_NAMES = Set
            .of("openssl", "libressl", "boringssl", "bouncycastle", "bouncy castle", "nss", "gnutls", "wolfssl",
                    "mbedtls", "libsodium", "nacl", "libgcrypt", "cryptlib", "jce", "javax.crypto.cipher",
                    "java.security", "cryptography", "pkcs#12", "pkcs12", "pkcs#7", "pkcs7", "pkcs#8", "pkcs8",
                    "pkcs#11", "pkcs11", "pem", "der", "x.509", "x509", "jwt", "jwe", "jws", "jwk", "cms", "pgp",
                    "openpgp", "keystore", "truststore", "block cipher", "stream cipher", "kem", "mac", "aead", "kdf",
                    "prf", "drbg", "signature", "hash", "digest", "cipher", "key exchange", "key agreement",
                    "public key", "private key", "symmetric", "asymmetric");

    static boolean isMaterial(Set<String> types, PqcRuleInput input) {
        // The asset-type gate is not redundant. A producer bug observed in the corpus stamps
        // relatedCryptoMaterialProperties onto algorithms and certificates, MaterialRedaction keeps that block in the
        // stored payload whatever the asset type, and the identity router ignores it -- so without this an algorithm
        // row carrying a stray {"type":"salt"} reads NOT_APPLICABLE instead of NOT_READY.
        return input.assetType() == CryptographicAssetType.RELATED_CRYPTO_MATERIAL && input.materialType() != null
                && types.contains(input.materialType());
    }

}
