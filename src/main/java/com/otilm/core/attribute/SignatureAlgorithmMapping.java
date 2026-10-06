package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.core.attribute.AlgorithmMapping.AttributeValue;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.LoggerFactory;

/**
 * Converts a signature algorithm to selected attributes and back. RSA and ECDSA use Core's scheme and digest fields;
 * algorithms without a split representation retain the original {@link SignatureAlgorithmAttribute}. Connector
 * capabilities and compatibility with a particular key are validated by the caller.
 */
public final class SignatureAlgorithmMapping {

    private static final UUID SCHEME_UUID = UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID);
    private static final UUID DIGEST_UUID = UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID);

    private static final Map<SignatureAlgorithm, List<AttributeValue>> SPLIT_ATTRIBUTES = Map
            .of(SignatureAlgorithm.SHA256_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_512),
                    SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_512),
                    SignatureAlgorithm.SHA256_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_512));

    private static final AlgorithmMapping<SignatureAlgorithm> MAPPING = new AlgorithmMapping<>("Signature",
            SignatureAlgorithmAttribute.ATTRIBUTE_UUID, SignatureAlgorithmAttribute.NAME,
            SignatureAlgorithmAttribute::request, SignatureAlgorithm::lookupByCode, SPLIT_ATTRIBUTES,
            "Signature attributes do not match a known RSA or ECDSA field combination.",
            LoggerFactory.getLogger(SignatureAlgorithmMapping.class));

    private SignatureAlgorithmMapping() {
    }

    /**
     * Converts a signature algorithm into the attributes that represent it.
     *
     * <p>
     * The shared mapping provides a scheme and digest for mapped RSA algorithms, or a digest alone for mapped ECDSA
     * algorithms. An algorithm without a split mapping, such as ML-DSA, retains its complete code in a single
     * {@code signatureAlgorithm} attribute; its identity is never replaced by an empty attribute list.
     *
     * <p>
     *
     * @param algorithm the non-null signature algorithm to represent
     * @return the split attributes, or one original signature-algorithm attribute when no split mapping exists
     * @throws NullPointerException when the algorithm is null
     */
    public static List<RequestAttribute> toAttributes(SignatureAlgorithm algorithm) {
        return MAPPING.toAttributes(algorithm);
    }

    /**
     * Resolves an exact selection regardless of attribute order or DTO version. UUID, name and a single string value
     * identify each field; duplicate, extra or malformed fields are refused. The original signature algorithm is read
     * only when it is the sole attribute. A digest alone represents ECDSA; callers must validate required RSA fields
     * against the key before invoking this conversion.
     *
     * @param attributes only the algorithm-selection attributes, without other connector operation attributes
     * @throws ValidationException when the attributes identify no signature algorithm
     */
    public static SignatureAlgorithm toAlgorithm(List<RequestAttribute> attributes) {
        return MAPPING.toAlgorithm(attributes);
    }

    private static List<AttributeValue> rsa(RsaSignatureScheme scheme, DigestAlgorithm digestAlgorithm) {
        AttributeValue schemeValue = AttributeValue
                .string(SCHEME_UUID, RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, scheme.getCode());
        AttributeValue digestValue = digest(digestAlgorithm);
        return List.of(schemeValue, digestValue);
    }

    private static List<AttributeValue> ecdsa(DigestAlgorithm digestAlgorithm) {
        AttributeValue digestValue = digest(digestAlgorithm);
        return List.of(digestValue);
    }

    private static AttributeValue digest(DigestAlgorithm digestAlgorithm) {
        return AttributeValue
                .string(DIGEST_UUID, RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, digestAlgorithm.getCode());
    }

}
