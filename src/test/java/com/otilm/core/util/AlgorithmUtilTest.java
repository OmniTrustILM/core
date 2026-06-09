package com.otilm.core.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class AlgorithmUtilTest {

    @Test
    public void testGetDigestAlgorithm() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        String digestAlgorithm = AlgorithmUtil.getDigestAlgorithm("1.3.14.3.2.26");
        Assertions.assertEquals(digestAlgorithm, "SHA-1");
    }


    @Test
    public void testGetSignatureAlgorithm() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        String digestAlgorithm = AlgorithmUtil.getSignatureAlgorithmName("1.3.14.3.2.26", "RSA");
        Assertions.assertEquals(digestAlgorithm, "SHA-1withRSA");
    }

    @Test
    public void testGetSignatureAlgorithm_exception() {
        Security.addProvider(new BouncyCastleProvider());
        Assertions.assertThrows(NoSuchAlgorithmException.class, () -> AlgorithmUtil.getSignatureAlgorithmName("11.3.14.3.2.26", "RSA"));
    }

    @Test
    public void testGetDigestAlgorithm_exception() {
        Security.addProvider(new BouncyCastleProvider());
        Assertions.assertThrows(NoSuchAlgorithmException.class, () -> AlgorithmUtil.getDigestAlgorithm("11.3.14.3.2.26"));
    }
}
