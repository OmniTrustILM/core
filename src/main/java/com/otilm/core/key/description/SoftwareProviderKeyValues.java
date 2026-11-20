package com.otilm.core.key.description;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Reads the custom map the v1 software provider stores for a private key it holds. The map names a curve by its stable
 * BouncyCastle name and a post-quantum parameter set by its parts.
 */
public final class SoftwareProviderKeyValues {

    private static final String CURVE_NAME = "curve.name";
    private static final String FALCON_DEGREE = "degree";
    private static final String MLDSA_LEVEL = "level";
    private static final String SECURITY_CATEGORY = "securityCategory";
    private static final String SLHDSA_HASH = "hash";
    private static final String SLHDSA_TRADEOFF = "tradeoff";
    private static final String PREHASH = "prehash";
    private static final String PREHASHED_SUFFIX = "-WITH-";

    private static final Map<String, ASN1ObjectIdentifier> FALCON_BY_DEGREE = Map
            .of("512", BCObjectIdentifiers.falcon_512, "1024", BCObjectIdentifiers.falcon_1024);
    private static final Map<String, ASN1ObjectIdentifier> MLDSA_BY_LEVEL = Map
            .of("2", NISTObjectIdentifiers.id_ml_dsa_44, "3", NISTObjectIdentifiers.id_ml_dsa_65, "5",
                    NISTObjectIdentifiers.id_ml_dsa_87);
    private static final Map<String, ASN1ObjectIdentifier> HASH_MLDSA_BY_LEVEL = Map
            .of("2", NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, "3",
                    NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, "5",
                    NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);
    private static final Map<String, ASN1ObjectIdentifier> MLKEM_BY_CATEGORY = Map
            .of("1", NISTObjectIdentifiers.id_alg_ml_kem_512, "3", NISTObjectIdentifiers.id_alg_ml_kem_768, "5",
                    NISTObjectIdentifiers.id_alg_ml_kem_1024);
    private static final Map<String, String> SLHDSA_SIZE_BY_CATEGORY = Map.of("1", "128", "3", "192", "5", "256");
    private static final Map<String, String> SLHDSA_FORM_BY_TRADEOFF = Map.of("FAST", "F", "SMALL", "S");

    private static final ObjectMapper JSON = ObjectMapperFactory.storage();
    private static final TypeReference<Map<String, String>> STRING_MAP = new TypeReference<>() {
    };

    private SoftwareProviderKeyValues() {
    }

    /**
     * Reads the parameters a stored custom map names for a key of the algorithm.
     *
     * @param algorithm the algorithm the item states
     * @param material the stored key data, a custom map as JSON for the software provider's keys
     * @return the parameters, present when the data is a custom map naming parameters Core knows
     */
    public static Optional<KeyParameters> parametersOf(KeyAlgorithm algorithm, KeyMaterial material) {
        if (material == null || material.format() != KeyFormat.CUSTOM || material.serializedValue() == null) {
            return Optional.empty();
        }
        try {
            return parametersOf(algorithm, JSON.readValue(material.serializedValue(), STRING_MAP));
        } catch (JsonProcessingException e) {
            return Optional.empty();
        }
    }

    /**
     * Reads the parameters a custom map names for a key of the algorithm.
     *
     * @param algorithm the algorithm the item states
     * @param values the custom map
     * @return the parameters, present when the map names parameters Core knows
     */
    public static Optional<KeyParameters> parametersOf(KeyAlgorithm algorithm, Map<String, String> values) {
        if (algorithm == null || values == null) {
            return Optional.empty();
        }
        Optional<AlgorithmIdentifier> identifier = switch (algorithm) {
            case ECDSA -> curveIdentifier(values.get(CURVE_NAME));
            case FALCON -> bare(lookUp(FALCON_BY_DEGREE, values, FALCON_DEGREE));
            case MLDSA -> bare(lookUp(prehashed(values) ? HASH_MLDSA_BY_LEVEL : MLDSA_BY_LEVEL, values, MLDSA_LEVEL));
            case SLHDSA -> bare(slhDsaOid(values));
            case MLKEM -> bare(lookUp(MLKEM_BY_CATEGORY, values, SECURITY_CATEGORY));
            default -> Optional.empty();
        };
        return identifier.map(read -> new KeyParameters(read, null));
    }

    private static Optional<AlgorithmIdentifier> curveIdentifier(String curveName) {
        ASN1ObjectIdentifier curve = curveName == null ? null : ECNamedCurveTable.getOID(curveName);
        return curve == null
                ? Optional.empty()
                : Optional.of(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(curve)));
    }

    private static Optional<AlgorithmIdentifier> bare(ASN1ObjectIdentifier oid) {
        return Optional.ofNullable(oid).map(AlgorithmIdentifier::new);
    }

    /** The SLH-DSA OID whose parameter-set code the parts spell, with the digest suffix of a prehashing key. */
    private static ASN1ObjectIdentifier slhDsaOid(Map<String, String> values) {
        String size = lookUp(SLHDSA_SIZE_BY_CATEGORY, values, SECURITY_CATEGORY);
        String form = lookUp(SLHDSA_FORM_BY_TRADEOFF, values, SLHDSA_TRADEOFF);
        String hash = values.get(SLHDSA_HASH);
        if (size == null || form == null || hash == null) {
            return null;
        }
        String code = "SLH-DSA-" + hash + "-" + size + form;
        String prehashedCode = code + PREHASHED_SUFFIX;
        return KeyParameterTable
                .slhDsaOidNamed(prehashed(values) ? name -> name.startsWith(prehashedCode) : code::equals)
                .orElse(null);
    }

    /** A missing value finds nothing. A {@code Map.of} table throws on a null key. */
    private static <T> T lookUp(Map<String, T> table, Map<String, String> values, String key) {
        String value = values.get(key);
        return value == null ? null : table.get(value);
    }

    private static boolean prehashed(Map<String, String> values) {
        return Boolean.parseBoolean(values.get(PREHASH));
    }
}
