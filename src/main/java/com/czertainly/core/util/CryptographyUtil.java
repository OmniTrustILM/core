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

    /**
     * Resolves the signature algorithm name. Derives the PQC parameter-spec name from raw public-key bytes. Use it when no
     * pre-computed name is available; on the signing hot path prefer the overload taking {@code pqcParameterSpecName}.
     */
    public static String resolveSignatureAlgorithmName(KeyAlgorithm keyAlgorithm, String publicKey, List<? extends RequestAttribute> signatureAttributes) {
        return resolveSignatureAlgorithmName(keyAlgorithm, signatureAttributes, resolvePqcParameterSpecName(keyAlgorithm, publicKey));
    }

    /**
     * Resolves the signature algorithm name; used by the signing hot path.
     *
     * <p>
     * Callers stay algorithm-agnostic and pass both inputs; this method picks the one that applies:
     * <ul>
     *   <li>RSA / ECDSA — <strong>request-intrinsic</strong>: built from {@code signatureAttributes} (digest and scheme),
     *       which only exist per signing request; {@code pqcParameterSpecName} is {@code null} and ignored.</li>
     *   <li>FALCON / ML-DSA / SLH-DSA — <strong>key-intrinsic</strong>: the name <em>is</em> the key's parameter set, so
     *       {@code pqcParameterSpecName} (pre-resolved once at key-model build time) is returned verbatim.</li>
     * </ul>
     *
     * @param keyAlgorithm         the key algorithm
     * @param signatureAttributes  signing operation attributes (read for RSA / ECDSA)
     * @param pqcParameterSpecName the pre-computed parameter-spec name for PQC algorithms; ignored for RSA / ECDSA
     */
    public static String resolveSignatureAlgorithmName(KeyAlgorithm keyAlgorithm, List<? extends RequestAttribute> signatureAttributes, String pqcParameterSpecName) {
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
                if (pqcParameterSpecName == null) {
                    throw new ValidationException(
                            ValidationError.create("pqcParameterSpecName is required for PQC algorithm " + keyAlgorithm));
                }
                return pqcParameterSpecName;
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
