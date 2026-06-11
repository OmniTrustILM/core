package com.otilm.core.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Class contains the common operations and helper functions to process the acme request
 */
public class AcmeCommonHelper {

    private static final Integer COMMON_EXPIRES_IN_SECONDS = 10 * 60 * 60;

    public static Date getDefaultExpires() {
        return new Date(new Date().getTime() + COMMON_EXPIRES_IN_SECONDS);
    }

    public static String keyAuthorizationGenerator(String token, String publicKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(publicKey.getBytes(StandardCharsets.UTF_8));
        return token + "." + Base64.getEncoder().encodeToString(hash).replace("=", "");
    }

    public static String createKeyAuthorization(String token, PublicKey publicKey) throws IllegalArgumentException {
        try {
            return token + "." + getJwkFromPublicKey(publicKey).computeThumbprint("SHA-256").toString();
        } catch (JOSEException var3) {
            throw new IllegalArgumentException(var3);
        }
    }

    public static JWK getJwkFromPublicKey(PublicKey publicKey) throws IllegalArgumentException {
        if (publicKey instanceof ECPublicKey key) {
            return (new ECKey.Builder(Curve.P_256, key)).build();
        } else if (publicKey instanceof RSAPublicKey key) {
            return (new com.nimbusds.jose.jwk.RSAKey.Builder(key)).build();
        } else {
            throw new IllegalArgumentException("Unsupported public key type.");
        }
    }

    public static String getStringFromDate(Date date) {
        if (date == null) {
            return null;
        }
        DateTimeFormatter formatter = DateTimeFormatter
                .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SS'Z'")
                .withZone(ZoneId.of("UTC"));
        return formatter.format(date.toInstant());
    }

    public static Date getDateFromString(String date) {
        if (date == null || date.isEmpty()) {
            return null;
        }
        DateTimeFormatter formatter = DateTimeFormatter
                .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SS'Z'")
                .withZone(ZoneId.of("UTC"));
        return new Date(Instant.from(formatter.parse(date)).getEpochSecond());
    }

    public static Date addSeconds(Date date, int seconds) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.SECOND, seconds);
        return calendar.getTime();
    }

    private Map<String, Object> generateJWK(PublicKey publicKey) {
        RSAPublicKey rsa = (RSAPublicKey) publicKey;
        Map<String, Object> values = new HashMap<>();
        values.put("kty", rsa.getAlgorithm()); // getAlgorithm() returns kty not algorithm
        values.put("n", Base64.getUrlEncoder().encodeToString(rsa.getModulus().toByteArray()));
        values.put("e", Base64.getUrlEncoder().encodeToString(rsa.getPublicExponent().toByteArray()));
        return values;
    }
}
