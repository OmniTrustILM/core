package com.czertainly.core.util;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.attribute.EcdsaSignatureAttributes;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPublicKey;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPublicKey;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

public class CryptographyUtil {
    public static AlgorithmIdentifier prepareSignatureAlgorithm(KeyAlgorithm keyAlgorithm, String publicKey, List<RequestAttribute> signatureAttributes) {
        return getAlgorithmIdentifierInstance(resolveSignatureAlgorithmName(keyAlgorithm, publicKey, signatureAttributes));
    }

    public static String resolveSignatureAlgorithmName(KeyAlgorithm keyAlgorithm, String publicKey, List<? extends RequestAttribute> signatureAttributes) {
        switch (keyAlgorithm) {
            case RSA -> {
                final RsaSignatureScheme scheme = RsaSignatureScheme.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                        RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, signatureAttributes, StringAttributeContentV2.class)
                                .getData()
                );
                final DigestAlgorithm digest = DigestAlgorithm.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, signatureAttributes, StringAttributeContentV2.class)
                                .getData()
                );

                String name = digest.getProviderName() + "WITHRSA";
                if (scheme == RsaSignatureScheme.PSS) {
                    name += "ANDMGF1";
                }
                return name;
            }
            case ECDSA -> {
                final DigestAlgorithm digest = DigestAlgorithm.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                        EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, signatureAttributes, StringAttributeContentV2.class)
                                .getData()
                );
                return digest.getProviderName() + "WITHECDSA";
            }
            case FALCON, MLDSA, SLHDSA -> {
                return resolvePqcParameterSpecName(keyAlgorithm, publicKey);
            }
            default -> throw new ValidationException(
                    ValidationError.create("Cryptographic algorithm not supported"));
        }
    }

    /**
     * Resolves the post-quantum signature parameter-spec name for FALCON / ML-DSA / SLH-DSA public keys, and returns
     * {@code null} for every other algorithm. The name is derived solely from the public key.
     *
     * @param keyAlgorithm the key algorithm
     * @param publicKey    Base64-encoded {@code SubjectPublicKeyInfo}; read only for PQC algorithms
     * @return the parameter-spec name for FALCON/ML-DSA/SLH-DSA, {@code null} otherwise
     * @throws ValidationException if a PQC public key cannot be parsed
     */
    public static String resolvePqcParameterSpecName(KeyAlgorithm keyAlgorithm, String publicKey) {
        if (publicKey == null) {
            return switch (keyAlgorithm) {
                case FALCON, MLDSA, SLHDSA -> throw new ValidationException(
                        ValidationError.create("PQC algorithm requires a public key to derive the parameter-spec name"));
                default -> null;
            };
        }
        // IOException is declared by each BC constructor but not triggered by any known input —
        // caught defensively in case a future BC version starts throwing it for malformed payloads.
        switch (keyAlgorithm) {
            case FALCON -> {
                try {
                    return new BCFalconPublicKey(
                            SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(publicKey)))
                            .getParameterSpec().getName();
                } catch (IOException | IllegalArgumentException | ClassCastException e) {
                    throw new ValidationException(ValidationError.create("Failed parsing PQC public key to derive parameter-spec name"));
                }
            }
            case MLDSA -> {
                try {
                    return new BCMLDSAPublicKey(
                            SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(publicKey)))
                            .getParameterSpec().getName();
                } catch (IOException | IllegalArgumentException | ClassCastException e) {
                    throw new ValidationException(ValidationError.create("Failed parsing PQC public key to derive parameter-spec name"));
                }
            }
            case SLHDSA -> {
                try {
                    return new BCSLHDSAPublicKey(
                            SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(publicKey)))
                            .getParameterSpec().getName();
                } catch (IOException | IllegalArgumentException | ClassCastException e) {
                    throw new ValidationException(ValidationError.create("Failed parsing PQC public key to derive parameter-spec name"));
                }
            }
            default -> {
                return null;
            }
        }
    }

    public static AlgorithmIdentifier getAlgorithmIdentifierInstance(String algorithm) {
        return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
    }

    public static KeyFormat getPublicKeyFormat(byte[] encodedPublicKey) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encodedPublicKey));
            return spki != null ? KeyFormat.SPKI : KeyFormat.RAW;
        } catch (IOException | IllegalArgumentException e) {
            return KeyFormat.RAW;
        }

    }
}
