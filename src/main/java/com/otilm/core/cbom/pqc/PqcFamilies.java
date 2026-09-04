package com.otilm.core.cbom.pqc;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Every ratified algorithm family, and what it means for post-quantum readiness.
 *
 * <p>
 * <b>Keyed on the ratified spelling, and complete by test rather than by intention.</b> The keys are the entries of
 * {@code identity-tables.json}'s {@code algorithmFamilies}, which is the union of the CycloneDX registry tokens and the
 * PQC pseudo-families the identity specification added -- so a family that reaches a stored row has an entry here or
 * the build is red. {@code PqcFamiliesTest} asserts that in both directions: no ratified family without a disposition,
 * and no disposition for a family the tables do not name. Without it a new pseudo-family would reach {@code unknown}
 * silently, which is exactly the miss the acceptance criteria forbid.
 *
 * <p>
 * <b>Why this table is hand-authored, and what is meant to replace it.</b> core#2196's ruling C12 moves the five
 * key-affecting Java constants into the generated artifact and generates a {@code pqcFamilies} set, because the one
 * living in {@code AssetNormalizer} had drifted -- 8 of 30 candidates missing. That ruling is carried to core#2165 and
 * unimplemented; {@code identity-tables.json} has no {@code pqcFamilies} key yet. This map is shaped so it can be
 * absorbed when it lands: the keys are already the ratified spellings, so the swap is a lookup change and not a
 * re-authoring. Until then this is a second hand-maintained crypto list, which is the condition C12 exists to end --
 * hence the completeness test, which is what a generated table would otherwise have given for free.
 *
 * <p>
 * <b>The registry names no pre-standard candidate.</b> Kyber, Dilithium, Falcon, SPHINCS+, Classic McEliece and the
 * rest reach this table only as pseudo-families, and {@code FN-DSA} -- the standardised name for Falcon -- is in
 * neither table under any spelling, so a document using it resolves to no family at all and falls to
 * {@link PqcRules#FAMILY_UNRESOLVED}. Adding it is a generator change that re-keys rows, so it is core#2168's, not this
 * rule set's.
 */
public final class PqcFamilies {

    private static final Map<String, FamilyClass> DISPOSITION = build();

    private PqcFamilies() {
    }

    /** The disposition of a ratified family spelling, or {@code null} for a token no table names. */
    public static FamilyClass of(String ratifiedSpelling) {
        return ratifiedSpelling == null ? null : DISPOSITION.get(ratifiedSpelling);
    }

    public static Map<String, FamilyClass> dispositions() {
        return DISPOSITION;
    }

    private static Map<String, FamilyClass> build() {
        Map<String, FamilyClass> map = new LinkedHashMap<>();

        // -- Factorisation and discrete logarithm: the migration surface itself -------------------------------------
        put(map, FamilyClass.SHOR_BREAKABLE, "RSA", "RSA-X931", "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PKCS1",
                "RSASSA-PSS", "DSA", "EC", "ECDH", "ECDSA", "ECIES", "EdDSA", "ElGamal", "FFDH", "MQV", "SM2", "SM9",
                "BLS", "J-PAKE", "SPAKE2", "SPAKE2PLUS", "SRP", "OPAQUE", "X3DH", "HPKE");

        // -- Symmetric and hash-based, unbroken --------------------------------------------------------------------
        put(map, FamilyClass.QUANTUM_RESISTANT_SYMMETRIC, "AES", "ARIA", "CAMELLIA", "SEED", "SM4", "Serpent",
                "Twofish", "CAST6", "RC6", "IDEA", "Ascon", "ChaCha", "ChaCha20", "Salsa20", "RABBIT", "HC", "SNOW3G",
                "ZUC", "MILENAGE", "TUAK", "Fernet", "SHA-2", "SHA-3", "BLAKE2", "BLAKE3", "SM3", "RIPEMD", "Whirlpool",
                "SipHash", "Poly1305", "HMAC", "CMAC", "UMAC", "HKDF", "ANSI-KDF", "SP800-108", "SP800-56C", "SSH-KDF",
                "TLS-PRF", "IKE-PRF", "PBKDF2", "PBES2", "PBMAC1", "Argon2", "bcrypt", "scrypt", "yescrypt", "CTR_DRBG",
                "HMAC_DRBG", "Hash_DRBG", "Fortuna", "Yarrow");

        // -- Symmetric or hash-based, but broken or deprecated classically -----------------------------------------
        put(map, FamilyClass.CLASSICAL_LEGACY, "DES", "3DES", "RC2", "RC4", "RC5", "Blowfish", "CAST5", "Skipjack",
                "A5/1", "A5/2", "CMEA", "3GPP-XOR", "MD2", "MD4", "MD5", "SHA-1", "PBKDF1", "PBES1");

        // -- Standardised post-quantum ------------------------------------------------------------------------------
        put(map, FamilyClass.PQC_STANDARDIZED, "ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS");

        // -- Pre-standard post-quantum candidates -------------------------------------------------------------------
        put(map, FamilyClass.PQC_PRESTANDARD, "Kyber", "Dilithium", "Falcon", "SPHINCS+", "NTRU", "NTRU-Prime",
                "FrodoKEM", "BIKE", "HQC", "Classic McEliece", "GeMSS", "Picnic", "SQIsign", "LESS", "PERK", "RYDE",
                "MIRATH", "QR-UOV", "HAWK", "Raccoon", "AIMer", "MAYO", "UOV", "SNOVA", "CROSS", "MQOM");

        // -- Post-quantum candidates broken by cryptanalysis --------------------------------------------------------
        put(map, FamilyClass.PQC_BROKEN, "SIKE", "Rainbow");

        // -- Named hybrids -----------------------------------------------------------------------------------------
        put(map, FamilyClass.PQC_HYBRID, "X-Wing");

        // -- One token, several primitive kinds ---------------------------------------------------------------------
        put(map, FamilyClass.FAMILY_AMBIGUOUS, "GOST");

        return Map.copyOf(map);
    }

    private static void put(Map<String, FamilyClass> map, FamilyClass disposition, String... families) {
        for (String family : families) {
            FamilyClass previous = map.put(family, disposition);
            if (previous != null) {
                throw new IllegalStateException(
                        "Family " + family + " is dispositioned twice: " + previous + " and " + disposition);
            }
        }
    }
}
