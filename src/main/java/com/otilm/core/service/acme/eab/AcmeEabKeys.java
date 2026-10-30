package com.otilm.core.service.acme.eab;

import com.nimbusds.jose.util.Base64URL;
import com.otilm.core.util.RandomUtil;

/**
 * The textual form of an External Account Binding HMAC key. The key travels as text — generated for an operator to
 * store in a secret, stored as that secret's content, and passed to an ACME client as {@code --eab-hmac-key} — while
 * the MAC is computed over the bytes it decodes to.
 */
public final class AcmeEabKeys {

    /** 256 bits, the HS256 minimum, so every generated key can verify a binding. */
    private static final int KEY_BYTES = 32;

    private AcmeEabKeys() {
    }

    /** A fresh random key, base64url-encoded. */
    public static String generate() {
        return RandomUtil.generateRandomNonceBase64Url(KEY_BYTES);
    }

    /**
     * The MAC key bytes a stored key text decodes to. Both base64url and standard base64 are accepted, since the two
     * spell the same bytes and an operator may paste either into the secret.
     *
     * @throws UnusableEabKeyException when the text is not valid base64
     */
    public static byte[] decode(String keyText) {
        if (keyText == null || keyText.isBlank()) {
            throw new UnusableEabKeyException("binding key is empty");
        }
        String normalized = keyText.trim().replace('+', '-').replace('/', '_').replace("=", "");
        byte[] key = new Base64URL(normalized).decode();
        if (key.length == 0) {
            throw new UnusableEabKeyException("binding key is not valid base64");
        }
        return key;
    }
}
