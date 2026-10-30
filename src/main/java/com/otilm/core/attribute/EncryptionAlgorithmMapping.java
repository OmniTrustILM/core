package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import com.otilm.core.attribute.AlgorithmMapping.AttributeValue;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.LoggerFactory;

/**
 * Converts encryption profiles to Core's RSA selection fields and back. Connector capabilities and compatibility with a
 * particular key are validated by the caller.
 */
public final class EncryptionAlgorithmMapping {

    private static final UUID SCHEME_UUID = UUID.fromString(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID);
    private static final UUID HASH_UUID = UUID.fromString(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_UUID);
    private static final UUID MGF_UUID = UUID.fromString(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_UUID);

    private static final Map<EncryptionAlgorithm, List<AttributeValue>> SPLIT_ATTRIBUTES = Map
            .of(EncryptionAlgorithm.RSA_PKCS1_V1_5, List.of(scheme(RsaEncryptionScheme.PKCS1_v1_5)),
                    EncryptionAlgorithm.RSA_OAEP_SHA1, oaep(DigestAlgorithm.SHA_1), EncryptionAlgorithm.RSA_OAEP_SHA256,
                    oaep(DigestAlgorithm.SHA_256), EncryptionAlgorithm.RSA_OAEP_SHA384, oaep(DigestAlgorithm.SHA_384),
                    EncryptionAlgorithm.RSA_OAEP_SHA512, oaep(DigestAlgorithm.SHA_512));

    private static final AlgorithmMapping<EncryptionAlgorithm> MAPPING = new AlgorithmMapping<>("Encryption",
            EncryptionAlgorithmAttribute.ATTRIBUTE_UUID, EncryptionAlgorithmAttribute.NAME,
            EncryptionAlgorithmAttribute::request, EncryptionAlgorithm::lookupByCode, SPLIT_ATTRIBUTES,
            "Encryption attributes do not match a known RSA field combination.",
            LoggerFactory.getLogger(EncryptionAlgorithmMapping.class));

    private EncryptionAlgorithmMapping() {
    }

    /**
     * Returns V3 fields: the scheme alone for PKCS1 v1.5, or scheme, hash and MGF=true for OAEP. OAEP profiles fix MGF1
     * to the selected hash and the label to the empty string. An algorithm without a split mapping retains its original
     * encryptionAlgorithm selector.
     *
     * @param algorithm the non-null encryption algorithm to represent
     * @throws NullPointerException when the algorithm is null
     */
    public static List<RequestAttribute> toAttributes(EncryptionAlgorithm algorithm) {
        return MAPPING.toAttributes(algorithm);
    }

    /**
     * Resolves an exact V2 or V3 selection, independent of field order. UUID, name, content type and a single value
     * must match; duplicate, missing, extra and malformed fields are refused. The original encryptionAlgorithm selector
     * is accepted only when supplied alone. OAEP requires MGF=true; no profile represents MGF=false.
     *
     * @param attributes only algorithm-selection attributes, without other connector operation attributes
     * @throws ValidationException when no encryption algorithm matches
     * @throws NullPointerException when attributes is null
     */
    public static EncryptionAlgorithm toAlgorithm(List<RequestAttribute> attributes) {
        return MAPPING.toAlgorithm(attributes);
    }

    private static AttributeValue scheme(RsaEncryptionScheme scheme) {
        return AttributeValue
                .string(SCHEME_UUID, RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, scheme.getCode());
    }

    private static List<AttributeValue> oaep(DigestAlgorithm digest) {
        AttributeValue schemeValue = scheme(RsaEncryptionScheme.OAEP);
        AttributeValue hashValue = AttributeValue
                .string(HASH_UUID, RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, digest.getCode());
        AttributeValue mgfValue = AttributeValue
                .bool(MGF_UUID, RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME, true);
        return List.of(schemeValue, hashValue, mgfValue);
    }
}
