package com.otilm.core.util;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class AcmePublicKeyProcessor {

    public static String publicKeyPemStringFromObject(PublicKey publicKey) {
        byte[] pubKeyBytes = publicKey.getEncoded();
        String pubKeyString = Base64.getEncoder().encodeToString(pubKeyBytes);
        return pubKeyString;
    }

    public static PublicKey publicKeyObjectFromString(String publicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return CryptographyUtil.decodePublicKey(Base64.getDecoder().decode(publicKey));
    }

}
