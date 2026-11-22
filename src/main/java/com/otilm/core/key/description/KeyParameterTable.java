package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Core's table of key parameters: the algorithm of each AlgorithmIdentifier OID, the CycloneDX name of each curve, and
 * the signature-algorithm code and per-half size of each post-quantum parameter set.
 */
final class KeyParameterTable {

    /**
     * A post-quantum parameter set with the size in bits its standard gives each half.
     *
     * @param algorithm the algorithm the parameter set belongs to
     * @param name the signature-algorithm code naming it
     * @param publicKeyBits the size of its public key
     * @param privateKeyBits the size of its private key
     */
    record ParameterSet(KeyAlgorithm algorithm, String name, int publicKeyBits, int privateKeyBits) {

        int bits(KeyType half) {
            return half == KeyType.PUBLIC_KEY ? publicKeyBits : privateKeyBits;
        }
    }

    private static final Map<ASN1ObjectIdentifier, KeyAlgorithm> CLASSICAL_ALGORITHMS = Map
            .of(PKCSObjectIdentifiers.rsaEncryption, KeyAlgorithm.RSA, PKCSObjectIdentifiers.id_RSASSA_PSS,
                    KeyAlgorithm.RSA, PKCSObjectIdentifiers.id_RSAES_OAEP, KeyAlgorithm.RSA,
                    X509ObjectIdentifiers.id_ea_rsa, KeyAlgorithm.RSA, X9ObjectIdentifiers.id_ecPublicKey,
                    KeyAlgorithm.ECDSA);

    private static final ParameterSet FALCON_512 = new ParameterSet(KeyAlgorithm.FALCON, "FALCON-512", 7176, 10248);

    private static final ParameterSet FALCON_1024 = new ParameterSet(KeyAlgorithm.FALCON, "FALCON-1024", 14344, 18440);

    private static final Map<ASN1ObjectIdentifier, ParameterSet> PARAMETER_SETS = Map
            .ofEntries(mlDsa(NISTObjectIdentifiers.id_ml_dsa_44, "ML-DSA-44", 10496, 20480),
                    mlDsa(NISTObjectIdentifiers.id_ml_dsa_65, "ML-DSA-65", 15616, 32256),
                    mlDsa(NISTObjectIdentifiers.id_ml_dsa_87, "ML-DSA-87", 20736, 39168),
                    mlDsa(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, "ML-DSA-44-WITH-SHA512", 10496, 20480),
                    mlDsa(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, "ML-DSA-65-WITH-SHA512", 15616, 32256),
                    mlDsa(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, "ML-DSA-87-WITH-SHA512", 20736, 39168),
                    slhDsa128(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, "SLH-DSA-SHA2-128S"),
                    slhDsa128(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, "SLH-DSA-SHA2-128F"),
                    slhDsa128(NISTObjectIdentifiers.id_slh_dsa_shake_128s, "SLH-DSA-SHAKE-128S"),
                    slhDsa128(NISTObjectIdentifiers.id_slh_dsa_shake_128f, "SLH-DSA-SHAKE-128F"),
                    slhDsa128(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256,
                            "SLH-DSA-SHA2-128S-WITH-SHA256"),
                    slhDsa128(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256,
                            "SLH-DSA-SHA2-128F-WITH-SHA256"),
                    slhDsa128(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128,
                            "SLH-DSA-SHAKE-128S-WITH-SHAKE128"),
                    slhDsa128(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128,
                            "SLH-DSA-SHAKE-128F-WITH-SHAKE128"),
                    slhDsa192(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, "SLH-DSA-SHA2-192S"),
                    slhDsa192(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, "SLH-DSA-SHA2-192F"),
                    slhDsa192(NISTObjectIdentifiers.id_slh_dsa_shake_192s, "SLH-DSA-SHAKE-192S"),
                    slhDsa192(NISTObjectIdentifiers.id_slh_dsa_shake_192f, "SLH-DSA-SHAKE-192F"),
                    slhDsa192(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512,
                            "SLH-DSA-SHA2-192S-WITH-SHA512"),
                    slhDsa192(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512,
                            "SLH-DSA-SHA2-192F-WITH-SHA512"),
                    slhDsa192(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256,
                            "SLH-DSA-SHAKE-192S-WITH-SHAKE256"),
                    slhDsa192(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256,
                            "SLH-DSA-SHAKE-192F-WITH-SHAKE256"),
                    slhDsa256(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, "SLH-DSA-SHA2-256S"),
                    slhDsa256(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, "SLH-DSA-SHA2-256F"),
                    slhDsa256(NISTObjectIdentifiers.id_slh_dsa_shake_256s, "SLH-DSA-SHAKE-256S"),
                    slhDsa256(NISTObjectIdentifiers.id_slh_dsa_shake_256f, "SLH-DSA-SHAKE-256F"),
                    slhDsa256(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512,
                            "SLH-DSA-SHA2-256S-WITH-SHA512"),
                    slhDsa256(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512,
                            "SLH-DSA-SHA2-256F-WITH-SHA512"),
                    slhDsa256(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256,
                            "SLH-DSA-SHAKE-256S-WITH-SHAKE256"),
                    slhDsa256(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256,
                            "SLH-DSA-SHAKE-256F-WITH-SHAKE256"),
                    mlKem(NISTObjectIdentifiers.id_alg_ml_kem_512, "ML-KEM-512", 6400, 13056),
                    mlKem(NISTObjectIdentifiers.id_alg_ml_kem_768, "ML-KEM-768", 9472, 19200),
                    mlKem(NISTObjectIdentifiers.id_alg_ml_kem_1024, "ML-KEM-1024", 12544, 25344),
                    Map.entry(BCObjectIdentifiers.falcon_512, FALCON_512),
                    Map.entry(BCObjectIdentifiers.old_falcon_512, FALCON_512),
                    Map.entry(BCObjectIdentifiers.falcon_1024, FALCON_1024),
                    Map.entry(BCObjectIdentifiers.old_falcon_1024, FALCON_1024));

    /** SECG Koblitz prime curves, named in the CycloneDX registry by their SECG names. */
    private static final Set<ASN1ObjectIdentifier> SECG_KOBLITZ_CURVES = Set
            .of(SECObjectIdentifiers.secp192k1, SECObjectIdentifiers.secp224k1, SECObjectIdentifiers.secp256k1);

    private static final Map<ASN1ObjectIdentifier, String> CURVE_NAMES = curveNames();

    private KeyParameterTable() {
    }

    /**
     * Finds the algorithm whose keys open with an AlgorithmIdentifier OID.
     *
     * @param oid the identifier's OID
     * @return the algorithm, empty for an OID outside the table
     */
    static Optional<KeyAlgorithm> algorithmOf(ASN1ObjectIdentifier oid) {
        return Optional
                .ofNullable(CLASSICAL_ALGORITHMS.get(oid))
                .or(() -> parameterSet(oid).map(ParameterSet::algorithm));
    }

    static Optional<ParameterSet> parameterSet(ASN1ObjectIdentifier oid) {
        return Optional.ofNullable(PARAMETER_SETS.get(oid));
    }

    static Optional<String> curveName(ASN1ObjectIdentifier curveOid) {
        return Optional.ofNullable(CURVE_NAMES.get(curveOid));
    }

    private static Map<ASN1ObjectIdentifier, String> curveNames() {
        Map<ASN1ObjectIdentifier, String> names = new HashMap<>();
        SECG_KOBLITZ_CURVES.forEach(oid -> names.put(oid, SECNamedCurves.getName(oid)));
        Collections
                .list(TeleTrusTNamedCurves.getNames())
                .forEach(name -> names.put(TeleTrusTNamedCurves.getOID((String) name), (String) name));
        Collections
                .list(NISTNamedCurves.getNames())
                .forEach(name -> names.put(NISTNamedCurves.getOID((String) name), (String) name));
        return Map.copyOf(names);
    }

    private static Map.Entry<ASN1ObjectIdentifier, ParameterSet> mlDsa(ASN1ObjectIdentifier oid, String name,
            int publicKeyBits, int privateKeyBits) {
        return Map.entry(oid, new ParameterSet(KeyAlgorithm.MLDSA, name, publicKeyBits, privateKeyBits));
    }

    private static Map.Entry<ASN1ObjectIdentifier, ParameterSet> slhDsa128(ASN1ObjectIdentifier oid, String name) {
        return Map.entry(oid, new ParameterSet(KeyAlgorithm.SLHDSA, name, 256, 512));
    }

    private static Map.Entry<ASN1ObjectIdentifier, ParameterSet> slhDsa192(ASN1ObjectIdentifier oid, String name) {
        return Map.entry(oid, new ParameterSet(KeyAlgorithm.SLHDSA, name, 384, 768));
    }

    private static Map.Entry<ASN1ObjectIdentifier, ParameterSet> slhDsa256(ASN1ObjectIdentifier oid, String name) {
        return Map.entry(oid, new ParameterSet(KeyAlgorithm.SLHDSA, name, 512, 1024));
    }

    private static Map.Entry<ASN1ObjectIdentifier, ParameterSet> mlKem(ASN1ObjectIdentifier oid, String name,
            int publicKeyBits, int privateKeyBits) {
        return Map.entry(oid, new ParameterSet(KeyAlgorithm.MLKEM, name, publicKeyBits, privateKeyBits));
    }
}
