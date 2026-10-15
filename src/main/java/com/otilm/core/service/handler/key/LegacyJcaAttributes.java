package com.otilm.core.service.handler.key;

import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.core.attribute.EcdsaSignatureAttributes;
import com.otilm.core.attribute.RsaEncryptionAttributes;
import com.otilm.core.attribute.RsaSignatureAttributes;
import java.util.List;
import java.util.Objects;

/** Translates JCA algorithm names into the legacy cryptography provider's operation vocabulary. */
final class LegacyJcaAttributes {
    private LegacyJcaAttributes() {
    }

    static List<RequestAttribute> signature(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        int separator = algorithm.indexOf("with");
        if (separator < 0) {
            throw new NotSupportedException("Unsupported legacy signature algorithm.");
        }
        String digestName = algorithm.substring(0, separator);
        String scheme = algorithm.substring(separator + 4);
        DigestAlgorithm digest = switch (digestName) {
            case "NONE" -> null;
            case "MD5" -> DigestAlgorithm.MD5;
            case "SHA1" -> DigestAlgorithm.SHA_1;
            case "SHA224" -> DigestAlgorithm.SHA_224;
            case "SHA256" -> DigestAlgorithm.SHA_256;
            case "SHA384" -> DigestAlgorithm.SHA_384;
            case "SHA512" -> DigestAlgorithm.SHA_512;
            default -> throw new NotSupportedException("Unsupported legacy signature digest.");
        };
        if ("ECDSA".equals(scheme)) {
            return digest == null ? List.of() : List.of(EcdsaSignatureAttributes.buildRequestDigest(digest));
        }
        RsaSignatureScheme rsaScheme = switch (scheme) {
            case "RSA" -> RsaSignatureScheme.PKCS1_v1_5;
            case "RSA/PSS", "RSAandMGF1" -> RsaSignatureScheme.PSS;
            default -> throw new NotSupportedException("Unsupported legacy signature scheme.");
        };
        RequestAttribute selection = RsaSignatureAttributes.buildRequestRsaSigScheme(rsaScheme);
        return digest == null
                ? List.of(selection)
                : List.of(selection, RsaSignatureAttributes.buildRequestDigest(digest));
    }

    static List<RequestAttribute> cipher(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        switch (algorithm) {
            case "RSA", "RSA/NONE/PKCS1Padding", "RSA/ECB/PKCS1Padding" -> {
                return List.of(RsaEncryptionAttributes.buildRequestEncryptionScheme(RsaEncryptionScheme.PKCS1_v1_5));
            }
            case "RSA/NONE/OAEPWithSHA1AndMGF1Padding", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding" -> {
                return List
                        .of(RsaEncryptionAttributes.buildRequestEncryptionScheme(RsaEncryptionScheme.OAEP),
                                RsaEncryptionAttributes.buildRequestOaepHash(DigestAlgorithm.SHA_1),
                                RsaEncryptionAttributes.buildRequestOaepMgf(true));
            }
            default -> throw new NotSupportedException("No cipher attributes mapped for algorithm: " + algorithm);
        }
    }

}
