package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.util.KeySizeUtil;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Parameters Core reads from a key encoding. Reading is as lenient as stored certificates and v1 keys need.
 *
 * @param identifier the AlgorithmIdentifier the encoding opens with
 * @param modulusBits the RSA modulus size in bits, which the identifier leaves out
 */
public record KeyParameters(AlgorithmIdentifier identifier, Integer modulusBits) {

    /**
     * Reads a DER SubjectPublicKeyInfo.
     *
     * @param spki the encoding
     * @return the parameters, empty when the encoding is unreadable
     */
    public static Optional<KeyParameters> ofSpki(byte[] spki) {
        try {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki));
            return Optional.of(new KeyParameters(info.getAlgorithm(), publicModulusBits(info)));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * Reads a DER PKCS#8 PrivateKeyInfo.
     *
     * @param privateKeyInfo the encoding
     * @return the parameters, empty when the encoding is unreadable
     */
    public static Optional<KeyParameters> ofPrivateKeyInfo(byte[] privateKeyInfo) {
        try {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfo));
            return Optional.of(new KeyParameters(info.getPrivateKeyAlgorithm(), privateModulusBits(info)));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * Reads a DER AlgorithmIdentifier.
     *
     * @param identifier the encoding
     * @return the parameters, empty when the encoding is unreadable
     */
    public static Optional<KeyParameters> ofIdentifier(byte[] identifier) {
        try {
            return Optional
                    .of(new KeyParameters(AlgorithmIdentifier.getInstance(ASN1Primitive.fromByteArray(identifier)),
                            null));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * Reads key data in the form Core stores it: a base64 SubjectPublicKeyInfo, PKCS#8 PrivateKeyInfo or
     * AlgorithmIdentifier.
     *
     * @param material the stored key data, or null
     * @return the parameters, empty for another format or unreadable data
     */
    public static Optional<KeyParameters> ofStoredKeyData(KeyMaterial material) {
        if (material == null || material.format() == null) {
            return Optional.empty();
        }
        String keyData = material.serializedValue();
        return switch (material.format()) {
            case SPKI -> decoded(keyData).flatMap(KeyParameters::ofSpki);
            case PRKI -> decoded(keyData).flatMap(KeyParameters::ofPrivateKeyInfo);
            case ALGORITHM_IDENTIFIER -> decoded(keyData).flatMap(KeyParameters::ofIdentifier);
            case RAW, EPRKI, CUSTOM -> Optional.empty();
        };
    }

    /**
     * Encodes the identifier as Core stores it in an {@code AlgorithmIdentifier} key item.
     *
     * @return the base64 DER encoding
     */
    public String base64Identifier() {
        try {
            return Base64.getEncoder().encodeToString(identifier.getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            throw new IllegalStateException("AlgorithmIdentifier failed to encode", e);
        }
    }

    private static Optional<byte[]> decoded(String base64) {
        if (base64 == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Base64.getDecoder().decode(base64));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static Integer publicModulusBits(SubjectPublicKeyInfo info) {
        if (!isRsa(info.getAlgorithm())) {
            return null;
        }
        try {
            return KeySizeUtil.knownLength(RSAPublicKey.getInstance(info.parsePublicKey()).getModulus().bitLength());
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static Integer privateModulusBits(PrivateKeyInfo info) {
        if (!isRsa(info.getPrivateKeyAlgorithm())) {
            return null;
        }
        try {
            return KeySizeUtil.knownLength(RSAPrivateKey.getInstance(info.parsePrivateKey()).getModulus().bitLength());
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static boolean isRsa(AlgorithmIdentifier identifier) {
        return KeyParameterTable.algorithmOf(identifier.getAlgorithm()).orElse(null) == KeyAlgorithm.RSA;
    }
}
