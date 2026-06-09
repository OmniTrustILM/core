package com.czertainly.core.util;

import com.otilm.api.model.connector.secrets.content.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

class SecretsUtilTest {

    @Test
    void testFingerprintCalculation() throws NoSuchAlgorithmException, JsonProcessingException {

        BasicAuthSecretContent basicAuthSecretContent = new BasicAuthSecretContent("testUsername", "testPassword");
        BasicAuthSecretContent basicAuthSecretContentWithExtraProperty = new BasicAuthSecretContent("testUsername", "testPassword");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(basicAuthSecretContent), SecretsUtil.calculateSecretContentFingerprint(basicAuthSecretContentWithExtraProperty));

        Map<String, Object> key1 = new HashMap<>(Map.of("key1", "value1", "key2", "value2"));
        key1.put("key3", null);
        KeyValueSecretContent keyValueSecretContent1 = new KeyValueSecretContent(key1);
        Map<String, Object> key2 = new HashMap<>(Map.of("key2", "value2", "key1", "value1"));
        key2.put("key3", null);
        KeyValueSecretContent keyValueSecretContent2 = new KeyValueSecretContent(key2);
        KeyValueSecretContent keyValueSecretContent3 = new KeyValueSecretContent(Map.of("key2", "value2", "key1", "value1"));
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(keyValueSecretContent1), SecretsUtil.calculateSecretContentFingerprint(keyValueSecretContent2));
        Assertions.assertNotEquals(SecretsUtil.calculateSecretContentFingerprint(keyValueSecretContent1), SecretsUtil.calculateSecretContentFingerprint(keyValueSecretContent3));

        KeyStoreSecretContent keyStoreSecretContent = new KeyStoreSecretContent(KeyStoreType.PKCS12, "content", "password");
        KeyStoreSecretContent keyStoreSecretContent2 = new KeyStoreSecretContent(KeyStoreType.PKCS12, "content", "password2");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(keyStoreSecretContent), SecretsUtil.calculateSecretContentFingerprint(keyStoreSecretContent2));

        ApiKeySecretContent apiKeySecretContent = new ApiKeySecretContent("apiKeyValue");
        ApiKeySecretContent apiKeySecretContent2 = new ApiKeySecretContent("apiKeyValue");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(apiKeySecretContent), SecretsUtil.calculateSecretContentFingerprint(apiKeySecretContent2));

        PrivateKeySecretContent privateKeySecretContent = new PrivateKeySecretContent("privateKeyValue");
        PrivateKeySecretContent privateKeySecretContent2 = new PrivateKeySecretContent("privateKeyValue");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(privateKeySecretContent), SecretsUtil.calculateSecretContentFingerprint(privateKeySecretContent2));

        SecretKeySecretContent secretKeySecretContent = new SecretKeySecretContent("secretKeyValue");
        SecretKeySecretContent secretKeySecretContent2 = new SecretKeySecretContent("secretKeyValue");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(secretKeySecretContent), SecretsUtil.calculateSecretContentFingerprint(secretKeySecretContent2));

        JwtTokenSecretContent jwtTokenSecretContent = new JwtTokenSecretContent("jwtTokenValue");
        JwtTokenSecretContent jwtTokenSecretContent2 = new JwtTokenSecretContent("jwtTokenValue");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(jwtTokenSecretContent), SecretsUtil.calculateSecretContentFingerprint(jwtTokenSecretContent2));

        GenericSecretContent genericSecretContent = new GenericSecretContent("genericValue");
        GenericSecretContent genericSecretContent2 = new GenericSecretContent("genericValue");
        Assertions.assertEquals(SecretsUtil.calculateSecretContentFingerprint(genericSecretContent), SecretsUtil.calculateSecretContentFingerprint(genericSecretContent2));

    }
}
