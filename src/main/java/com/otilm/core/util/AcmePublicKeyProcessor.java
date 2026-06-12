package com.otilm.core.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AcmePublicKeyProcessor {

    public static String publicKeyPemStringFromObject(PublicKey publicKey) {
        byte[] pubKeyBytes = publicKey.getEncoded();
        String pubKeyString = Base64.getEncoder().encodeToString(pubKeyBytes);
        return pubKeyString;
    }

    public static PublicKey publicKeyObjectFromString(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicBytes = Base64.getDecoder().decode(publicKey);
        String oid = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(publicBytes)
                .getAlgorithm().getAlgorithm().toString();
        PublicKey publicKeyObject = KeyFactory.getInstance(oid, new org.bouncycastle.jce.provider.BouncyCastleProvider())
                .generatePublic(new X509EncodedKeySpec(publicBytes));
        return publicKeyObject;
    }

}
