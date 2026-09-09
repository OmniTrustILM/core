package com.otilm.core.cbom.pqc;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Every ratified algorithm family and what it means for post-quantum readiness, keyed on the ratified spelling.
 *
 * <p>
 * Hand-authored because core#2196's ruling C12 -- generate {@code pqcFamilies} into the artifact -- is carried and
 * unimplemented. Shaped so C12 can absorb it: the keys are already the ratified spellings. {@code PqcFamiliesTest}
 * fails the build if the tables gain a family without a disposition, which is what a generated table would give free.
 *
 * <p>
 * The registry names no pre-standard candidate; they reach this table only as pseudo-families. FN-DSA is in no table
 * under any spelling, so a document using it elects the classical DSA family. Closing that needs a vocabulary act -- an
 * FN-DSA pseudo-family in the generator, landing with ruling C12 -- and no rule set can repair it.
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
                "Twofish", "CAST6", "RC6", "Ascon", "ChaCha", "ChaCha20", "Salsa20", "RABBIT", "HC", "SNOW3G", "ZUC",
                "MILENAGE", "TUAK", "Fernet", "SHA-2", "SHA-3", "BLAKE2", "BLAKE3", "SM3", "Whirlpool", "SipHash",
                "Poly1305", "HMAC", "CMAC", "UMAC", "HKDF", "ANSI-KDF", "SP800-108", "SP800-56C", "SSH-KDF", "TLS-PRF",
                "IKE-PRF", "PBKDF2", "PBES2", "PBMAC1", "Argon2", "bcrypt", "scrypt", "yescrypt", "CTR_DRBG",
                "HMAC_DRBG", "Hash_DRBG", "Fortuna");

        // -- Symmetric or hash-based, but broken or deprecated classically -----------------------------------------
        put(map, FamilyClass.CLASSICAL_LEGACY, "DES", "3DES", "RC2", "RC4", "RC5", "Blowfish", "CAST5", "Skipjack",
                "A5/1", "A5/2", "CMEA", "3GPP-XOR", "MD2", "MD4", "MD5", "SHA-1", "PBKDF1", "PBES1", "IDEA", "Yarrow");

        // -- Standardised post-quantum ------------------------------------------------------------------------------
        put(map, FamilyClass.PQC_STANDARDIZED, "ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS");

        // -- Pre-standard post-quantum candidates -------------------------------------------------------------------
        put(map, FamilyClass.PQC_PRESTANDARD, "Kyber", "Dilithium", "Falcon", "SPHINCS+", "NTRU", "NTRU-Prime",
                "FrodoKEM", "BIKE", "HQC", "Classic McEliece", "Picnic", "SQIsign", "LESS", "PERK", "RYDE", "MIRATH",
                "QR-UOV", "HAWK", "Raccoon", "AIMer", "MAYO", "UOV", "SNOVA", "CROSS", "MQOM");

        // -- Post-quantum candidates broken by cryptanalysis --------------------------------------------------------
        put(map, FamilyClass.PQC_BROKEN, "SIKE", "Rainbow", "GeMSS");

        // -- Named hybrids -----------------------------------------------------------------------------------------
        put(map, FamilyClass.PQC_HYBRID, "X-Wing");

        // -- One token, several primitive kinds ---------------------------------------------------------------------
        put(map, FamilyClass.FAMILY_AMBIGUOUS, "GOST", "RIPEMD");

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
