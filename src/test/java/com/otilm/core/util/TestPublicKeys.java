package com.otilm.core.util;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

/** Freshly generated public keys for tests that need real material. Each call is a new key. */
public final class TestPublicKeys {

    private TestPublicKeys() {
    }

    public static PublicKey rsaPublicKey() {
        return generate("RSA", 2048);
    }

    public static PublicKey ecPublicKey() {
        return generate("EC", 256);
    }

    /** The key's SubjectPublicKeyInfo, Base64-encoded, as a connector reports it. */
    public static String spkiBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private static PublicKey generate(String algorithm, int size) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(size);
            return generator.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
