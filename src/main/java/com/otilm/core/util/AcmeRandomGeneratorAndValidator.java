package com.otilm.core.util;

import com.nimbusds.jose.util.Base64URL;

import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * This class contains the methods for generating and validating the nonce
 * for all the ACME requests.
 * This class uses SecureRandom class from spring security for Nonce generation
 */
public class AcmeRandomGeneratorAndValidator {

    private static final Integer NONCE_SIZE = 32;
    private static final Integer RANDOM_ID_SIZE = 8;
    private static final Integer RANDOM_CHALLENGE_TOKEN_SIZE = 64;

    public static String generateNonce(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonceArray = new byte[NONCE_SIZE];
        secureRandom.nextBytes(nonceArray);
        return Base64URL.encode(nonceArray).toString();
    }

    public static String generateRandomId(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomArray = new byte[RANDOM_ID_SIZE];
        secureRandom.nextBytes(randomArray);
        String randomId = Base64URL.encode(randomArray).toString();
        return randomId.replace("/", "-");
    }

    public static String generateRandomTokenForValidation() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomArray = new byte[RANDOM_CHALLENGE_TOKEN_SIZE];
        secureRandom.nextBytes(randomArray);
        String randomId = Base64URL.encode(randomArray).toString();
        return randomId.replace("/","0");
    }
}