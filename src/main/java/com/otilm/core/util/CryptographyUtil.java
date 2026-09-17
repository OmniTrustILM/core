package com.otilm.core.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.EcdsaSignatureAttributes;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.model.crypto.KeyMaterial;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPublicKey;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPublicKey;

public class CryptographyUtil {
    private static final Map<KeyType, List<KeyUsage>> FORBIDDEN_TYPE_USAGES = Map
            .of(KeyType.PRIVATE_KEY, List.of(KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.WRAP), KeyType.PUBLIC_KEY,
                    List.of(KeyUsage.SIGN, KeyUsage.DECRYPT, KeyUsage.UNWRAP));
    private static final Map<KeyAlgorithm, List<KeyUsage>> FORBIDDEN_ALGORITHM_USAGES = Map
            .of(KeyAlgorithm.ECDSA, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));

    /**
     * Returns usages prohibited by the key type or algorithm.
     *
     * @param keyType non-null key type
     * @param keyAlgorithm non-null key algorithm
     * @return distinct prohibited usages in unspecified order; empty when neither input imposes restrictions
     */
    public static List<KeyUsage> getForbiddenUsages(KeyType keyType, KeyAlgorithm keyAlgorithm) {
        Set<KeyUsage> usages = new HashSet<>(FORBIDDEN_TYPE_USAGES.getOrDefault(keyType, List.of()));
        usages.addAll(FORBIDDEN_ALGORITHM_USAGES.getOrDefault(keyAlgorithm, List.of()));
        return List.copyOf(usages);
    }

    /**
     * Calculates a fingerprint from serialized key material.
     *
     * @param material key material, or null when no material is available
     * @return fingerprint, or null for absent material, format, or serialized value, or a custom format
     * @throws ValidationException if the fingerprint algorithm is unavailable
     */
    public static String calculateKeyFingerprint(KeyMaterial material) {
        if (material == null || material.format() == null || material.format() == KeyFormat.CUSTOM
                || material.serializedValue() == null) {
            return null;
        }
        try {
            byte[] serializedBytes = material.serializedValue().getBytes(StandardCharsets.UTF_8);
            return CertificateUtil.getThumbprint(serializedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new ValidationException("Failed to calculate key fingerprint.");
        }
    }

    public static AlgorithmIdentifier prepareSignatureAlgorithm(KeyAlgorithm keyAlgorithm, String publicKey,
            List<RequestAttribute> signatureAttributes) {
        return getAlgorithmIdentifierInstance(
                resolveSignatureAlgorithmName(keyAlgorithm, publicKey, signatureAttributes));
    }

    /**
     * Resolves the signature algorithm name. Derives the PQC parameter-spec name from raw public-key bytes. Use it when
     * no pre-computed name is available; on the signing hot path prefer the overload taking
     * {@code pqcParameterSpecName}.
     */
    public static String resolveSignatureAlgorithmName(KeyAlgorithm keyAlgorithm, String publicKey,
            List<? extends RequestAttribute> signatureAttributes) {
        return resolveSignatureAlgorithmName(keyAlgorithm, signatureAttributes,
                resolvePqcParameterSpecName(keyAlgorithm, publicKey));
    }

    /**
     * Resolves the signature algorithm name; used by the signing hot path.
     *
     * <p>
     * Callers stay algorithm-agnostic and pass both inputs; this method picks the one that applies:
     * <ul>
     * <li>RSA / ECDSA — <strong>request-intrinsic</strong>: built from {@code signatureAttributes} (digest and scheme),
     * which only exist per signing request; {@code pqcParameterSpecName} is {@code null} and ignored.</li>
     * <li>FALCON / ML-DSA / SLH-DSA — <strong>key-intrinsic</strong>: the name <em>is</em> the key's parameter set, so
     * {@code pqcParameterSpecName} (pre-resolved once at key-model build time) is returned verbatim.</li>
     * </ul>
     *
     * @param keyAlgorithm the key algorithm
     * @param signatureAttributes signing operation attributes (read for RSA / ECDSA)
     * @param pqcParameterSpecName the pre-computed parameter-spec name for PQC algorithms; ignored for RSA / ECDSA
     */
    public static String resolveSignatureAlgorithmName(KeyAlgorithm keyAlgorithm,
            List<? extends RequestAttribute> signatureAttributes, String pqcParameterSpecName) {
        switch (keyAlgorithm) {
            case RSA -> {
                final RsaSignatureScheme scheme = RsaSignatureScheme
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(
                                        RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, signatureAttributes,
                                        StringAttributeContentV2.class)
                                .getData());
                final DigestAlgorithm digest = DigestAlgorithm
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                                        signatureAttributes, StringAttributeContentV2.class)
                                .getData());

                String name = digest.getProviderName() + "WITHRSA";
                if (scheme == RsaSignatureScheme.PSS) {
                    name += "ANDMGF1";
                }
                return name;
            }
            case ECDSA -> {
                final DigestAlgorithm digest = DigestAlgorithm
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                                        signatureAttributes, StringAttributeContentV2.class)
                                .getData());
                return digest.getProviderName() + "WITHECDSA";
            }
            case FALCON, MLDSA, SLHDSA -> {
                if (pqcParameterSpecName == null) {
                    throw new ValidationException(ValidationError
                            .create("pqcParameterSpecName is required for PQC algorithm " + keyAlgorithm));
                }
                return pqcParameterSpecName;
            }
            default -> throw new ValidationException(ValidationError.create("Cryptographic algorithm not supported"));
        }
    }

    /**
     * Resolves the post-quantum signature parameter-spec name for FALCON / ML-DSA / SLH-DSA public keys, and returns
     * {@code null} for every other algorithm. The name is derived solely from the public key.
     *
     * @param keyAlgorithm the key algorithm
     * @param publicKey Base64-encoded {@code SubjectPublicKeyInfo}; read only for PQC algorithms
     * @return the parameter-spec name for FALCON/ML-DSA/SLH-DSA, {@code null} otherwise
     * @throws ValidationException if a PQC public key cannot be parsed
     */
    public static String resolvePqcParameterSpecName(KeyAlgorithm keyAlgorithm, String publicKey) {
        if (publicKey == null) {
            return switch (keyAlgorithm) {
                case FALCON, MLDSA, SLHDSA -> throw new ValidationException(ValidationError
                        .create("PQC algorithm requires a public key to derive the parameter-spec name"));
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
                            .getParameterSpec()
                            .getName();
                } catch (IOException | IllegalArgumentException | ClassCastException e) {
                    throw new ValidationException(
                            ValidationError.create("Failed parsing PQC public key to derive parameter-spec name"));
                }
            }
            case MLDSA -> {
                try {
                    return new BCMLDSAPublicKey(SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(publicKey)))
                            .getParameterSpec()
                            .getName();
                } catch (IOException | IllegalArgumentException | ClassCastException e) {
                    throw new ValidationException(
                            ValidationError.create("Failed parsing PQC public key to derive parameter-spec name"));
                }
            }
            case SLHDSA -> {
                try {
                    return new BCSLHDSAPublicKey(
                            SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(publicKey)))
                            .getParameterSpec()
                            .getName();
                } catch (IOException | IllegalArgumentException | ClassCastException e) {
                    throw new ValidationException(
                            ValidationError.create("Failed parsing PQC public key to derive parameter-spec name"));
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
