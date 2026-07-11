package com.otilm.core.integration.util;

import com.otilm.core.util.AcmePublicKeyProcessor;
import com.otilm.core.util.AcmeRandomGeneratorAndValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

@SpringBootTest
public class AcmeUtilITest {

    @Test
    public void testNonceGeneration(){
        String nonce = AcmeRandomGeneratorAndValidator.generateNonce();
        Assertions.assertNotNull(nonce);
        Assertions.assertTrue(nonce.length() > 3);
    }

    @Test
    public void testRandomIdGeneration(){
        String nonce = AcmeRandomGeneratorAndValidator.generateRandomId();
        Assertions.assertNotNull(nonce);
        Assertions.assertTrue(nonce.length() > 3);
    }

    @Test
    public void testRandomTokenForValidation() {
        String nonce = AcmeRandomGeneratorAndValidator.generateRandomTokenForValidation();
        Assertions.assertNotNull(nonce);
        Assertions.assertTrue(nonce.length() > 3);
    }

    @Test
    public void testPublicKeyProcessing() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        String publicKeyString = AcmePublicKeyProcessor.publicKeyPemStringFromObject(publicKey);
        PublicKey pubkey1 = AcmePublicKeyProcessor.publicKeyObjectFromString(publicKeyString);
        Assertions.assertEquals(pubkey1, publicKey);
    }
}
