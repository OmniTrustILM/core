package com.otilm.core.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.key.description.KeyDescriber;
import com.otilm.core.key.description.KeyParameters;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

public class KeySizeUtil {

    private static final int UNKNOWN_LENGTH = -1;

    private KeySizeUtil() {
    }

    /**
     * An RSA or DSA key is sized by its own parameters, any other key by Core's parameter table, and an EC key the
     * table cannot size by its curve's field.
     *
     * @param publicKey Public Key of the certificate
     * @return Key Size of the public Key, or -1 when unknown
     */
    public static int getKeyLength(final PublicKey publicKey) {
        if (publicKey instanceof final RSAPublicKey rsaPublicKey) {
            return rsaPublicKey.getModulus().bitLength();
        } else if (publicKey instanceof final DSAPublicKey dsaPublicKey) {
            if (dsaPublicKey.getParams() != null) {
                return dsaPublicKey.getParams().getP().bitLength();
            } else {
                return dsaPublicKey.getY().bitLength();
            }
        }
        return describedLength(publicKey).or(() -> ecFieldSize(publicKey)).orElse(UNKNOWN_LENGTH);
    }

    /** A key length as Core records it: null in place of a length below 1. */
    public static Integer knownLength(Integer length) {
        return length != null && length > 0 ? length : null;
    }

    private static Optional<Integer> describedLength(PublicKey publicKey) {
        return KeyParameters
                .ofSpki(publicKey.getEncoded())
                .map(parameters -> KeyDescriber
                        .describe(parameters, KeyType.PUBLIC_KEY, KeyAlgorithm.UNKNOWN, null)
                        .length());
    }

    private static Optional<Integer> ecFieldSize(PublicKey publicKey) {
        if (publicKey instanceof final ECPublicKey ecPublicKey && ecPublicKey.getParams() != null) {
            return Optional.of(ecPublicKey.getParams().getCurve().getField().getFieldSize());
        }
        return Optional.empty();
    }
}
