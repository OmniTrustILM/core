package com.otilm.core.util;

import com.nimbusds.jose.util.Base64URL;

import java.security.SecureRandom;
import java.util.Base64;

public class RandomUtil {

    /**
     * This method generates a random nonce
     * @param size size of the nonce in bytes
     * @return nonce
     */
    public static byte[] generateRandomNonce(int size) {
        byte[] nonce = new byte[size];
        SecureRandom randomSource = new SecureRandom();
        randomSource.nextBytes(nonce);
        return nonce;
    }

    /**
     * This method generates a random nonce in Base64 format
     * @param size size of the nonce in bytes
     * @return nonce
     */
    public static String generateRandomNonceBase64(int size) {
        return new String(Base64.getEncoder().encode(generateRandomNonce(size)));
    }

    /**
     * This method generates a random nonce in Base64Url format
     * @param size size of the nonce in bytes
     * @return nonce
     */
    public static String generateRandomNonceBase64Url(int size) {
        return Base64URL.encode(generateRandomNonce(size)).toString();
    }
}
