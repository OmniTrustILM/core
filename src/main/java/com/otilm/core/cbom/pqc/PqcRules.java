package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The rule table: first match wins, and the last rule matches everything.
 *
 * <p>
 * Two orderings are load-bearing. Asset-type rules run first, because an asset that is not an algorithm has no family
 * to read. The hybrid rule runs before every family rule, because a hybrid's stored family is whichever construction
 * the grammar elected. That is not always the post-quantum one: measured, {@code X25519-Kyber768} stores {@code ECDH},
 * so a family-first order reports a migrated asset as un-migrated. (D17 moved {@code X25519-ML-KEM-768} itself onto the
 * {@code X-Wing} pseudo-family, so the worked example that used to appear here no longer shows the effect.)
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

    public static final String PARAMETER_SET = "parameterSet";

    public static final String CURVE = "curve";

    public static final String VARIANT = "variant";

    public static final String NAME = "name";

    public static final String HYBRID_COMPONENTS = "hybridComponents";

    public static final String MATERIAL_TYPE = "materialType";

    public static final String MATERIAL_SIZE = "materialSize";

    public static final String NIST_QUANTUM_SECURITY_LEVEL = "nistQuantumSecurityLevel";

    public static final Set<String> EVIDENCE_FIELDS = Set
            .of(ASSET_TYPE, ALGORITHM_FAMILY, PARAMETER_SET, CURVE, "mode", "padding", VARIANT, NAME, HYBRID_COMPONENTS,
                    MATERIAL_TYPE, MATERIAL_SIZE, NIST_QUANTUM_SECURITY_LEVEL);

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

    public static final int MIN_SYMMETRIC_KEY_BITS = 128;

    public static final String FAMILY_UNRESOLVED = "FAMILY-UNRESOLVED";

    public static final String HYBRID = "PQC-HYBRID";

    private PqcRules() {
    }

    static List<PqcRule> rulesFor(AssetNormalizer normalizer) {
        return List
                .of(
                        // ---- Asset types that carry no algorithm of their own -------------------------------------
                        new PqcRule("CERT-DEFERRED-V1",
                                input -> input.assetType() == CryptographicAssetType.CERTIFICATE,
                                PqcVerdict.NOT_APPLICABLE,
                                "A certificate's readiness is the readiness of the key it certifies, which this rule-set "
                                        + "generation does not resolve",
                                List.of(ASSET_TYPE)),
                        new PqcRule("PROTOCOL-NOT-ALGORITHM",
                                input -> input.assetType() == CryptographicAssetType.PROTOCOL,
                                PqcVerdict.NOT_APPLICABLE,
                                "A protocol is not an algorithm; readiness belongs to the algorithms it negotiates",
                                List.of(ASSET_TYPE)),
                        new PqcRule("ASSET-TYPE-UNROUTABLE",
                                input -> input.assetType() == null
                                        || input.assetType() == CryptographicAssetType.UNROUTABLE,
                                PqcVerdict.NOT_APPLICABLE,
                                "The producer named no asset type this platform routes, so there is no algorithm to "
                                        + "assess",
                                List.of(ASSET_TYPE)),

                        // ---- Material that is not a key -----------------------------------------------------------
                        new PqcRule("MATERIAL-NOT-KEY", input -> isMaterial(NON_KEY_MATERIAL, input),
                                PqcVerdict.NOT_APPLICABLE,
                                "This cryptographic material is not a key, so it is outside the readiness question",
                                List.of(ASSET_TYPE, MATERIAL_TYPE)),

                        // ---- Names that are not algorithm names ---------------------------------------------------
                        // Both yield to a resolved family: a producer that declares `RSA` on an asset it named `digest`
                        // has said what the asset is, and a 56-entry name list must not remove it from the inventory.
                        new PqcRule("NAME-CIPHER-SUITE",
                                input -> input.assetType() == CryptographicAssetType.ALGORITHM
                                        && PqcFamilies.of(input.algorithmFamily()) == null && input.name() != null
                                        && normalizer.isCipherSuiteName(input.name()),
                                PqcVerdict.NOT_APPLICABLE,
                                "The name denotes a cipher suite rather than a single algorithm; readiness belongs to its "
                                        + "component algorithms",
                                List.of(ASSET_TYPE, ALGORITHM_FAMILY, NAME)),
                        new PqcRule("NAME-NOT-AN-ALGORITHM",
                                input -> input.assetType() == CryptographicAssetType.ALGORITHM
                                        && PqcFamilies.of(input.algorithmFamily()) == null && isNonAlgorithmName(input),
                                PqcVerdict.NOT_APPLICABLE,
                                "The name denotes a library, an API, a container format or a construction category rather "
                                        + "than an algorithm",
                                List.of(ASSET_TYPE, ALGORITHM_FAMILY, NAME)),

                        // ---- Hybrids, before any family rule ------------------------------------------------------
                        // Algorithms only: a key's name may record the construction that produced it, and a 256-bit
                        // session key labelled with its hybrid KEX is decided by the symmetric rules below, not by the
                        // KEX. The verdict is the post-quantum component's, so the evaluator resolves it rather than
                        // this table. See PqcEvaluator#hybridDecision.
                        new PqcRule(HYBRID,
                                input -> input.assetType() == CryptographicAssetType.ALGORITHM && input.isHybrid(),
                                PqcVerdict.READY,
                                "A hybrid construction; its readiness is that of its post-quantum component",
                                List.of(ASSET_TYPE, ALGORITHM_FAMILY, HYBRID_COMPONENTS, NAME)),

                        // ---- Symmetric key material ---------------------------------------------------------------
                        // A key named after a broken primitive is decided by its family, not by its size. Measured:
                        // a secret-key named DES declaring 56 bits read UNKNOWN here, because a size under the
                        // ratified floor reads as absent and these arms never ask what the key is.
                        new PqcRule("MATERIAL-SYMMETRIC-READY",
                                input -> isMaterial(SYMMETRIC_MATERIAL, input) && !namesABrokenPrimitive(input)
                                        && input.materialSize() != null
                                        && input.materialSize() >= MIN_SYMMETRIC_KEY_BITS,
                                PqcVerdict.READY,
                                "A symmetric key of at least 128 bits; Grover's algorithm halves its strength but does not "
                                        + "break it",
                                List.of(ASSET_TYPE, MATERIAL_TYPE, MATERIAL_SIZE, ALGORITHM_FAMILY)),
                        new PqcRule("MATERIAL-SYMMETRIC-WEAK",
                                input -> isMaterial(SYMMETRIC_MATERIAL, input) && !namesABrokenPrimitive(input)
                                        && input.materialSize() != null
                                        && input.materialSize() < MIN_SYMMETRIC_KEY_BITS,
                                PqcVerdict.NOT_READY,
                                "A symmetric key whose declared size is below 128 bits, so Grover's algorithm leaves it "
                                        + "with no adequate strength",
                                List.of(ASSET_TYPE, MATERIAL_TYPE, MATERIAL_SIZE, ALGORITHM_FAMILY)),
                        new PqcRule("MATERIAL-SYMMETRIC-UNSIZED",
                                input -> isMaterial(SYMMETRIC_MATERIAL, input)
                                        && !namesABrokenPrimitive(input) && input.materialSize() == null,
                                PqcVerdict.UNKNOWN,
                                "A symmetric key whose declared size is absent or implausible, so its strength cannot "
                                        + "be affirmed",
                                List.of(ASSET_TYPE, MATERIAL_TYPE, MATERIAL_SIZE, ALGORITHM_FAMILY)));
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

    /**
     * A key whose own name resolves to a classically broken or Shor-breakable family is decided by that family rather
     * than by its declared size. {@code DES} is broken because it is DES, and the size arms cannot say so: a stated
     * size below the ratified floor reads as absent, and under 64 a bit count cannot be told from a byte count -- 32 is
     * either AES-256 in bytes or a broken key in bits. The name carries the finding without that ambiguity, and falling
     * through to the family rules keeps the row under the same {@code CLASSICAL-LEGACY} / {@code
     * CLASSICAL-SHOR} ids an operator already queries.
     */
    static boolean namesABrokenPrimitive(PqcRuleInput input) {
        if (input.isHybrid()) {
            // A session key labelled with the hybrid KEX that produced it is the key's own strength, not the KEX's,
            // and the elected family is whichever half the grammar picked. Leave those to the size arms.
            return false;
        }
        FamilyClass disposition = PqcFamilies.of(input.algorithmFamily());
        return disposition == FamilyClass.CLASSICAL_LEGACY || disposition == FamilyClass.SHOR_BREAKABLE;
    }

    static boolean isMaterial(Set<String> types, PqcRuleInput input) {
        // The asset-type gate is not redundant. A producer bug observed in the corpus stamps
        // relatedCryptoMaterialProperties onto algorithms and certificates, MaterialRedaction keeps that block in the
        // stored payload whatever the asset type, and the identity router ignores it -- so without this an algorithm
        // row carrying a stray {"type":"salt"} reads NOT_APPLICABLE instead of NOT_READY.
        return input.assetType() == CryptographicAssetType.RELATED_CRYPTO_MATERIAL && input.materialType() != null
                && types.contains(input.materialType());
    }

}
