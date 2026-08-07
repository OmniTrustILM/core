package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.core.service.cmp.CmpTestUtil;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtectionMacComputationTest {

    private static final String SECRET = "the-secret";

    @BeforeAll
    static void addProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void matchesMacTrueForTheKeyItWasBuiltWith() throws Exception {
        PKIMessage message = macMessage(SECRET);

        assertTrue(ProtectionMacValidator.matchesMac(message, SECRET.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void matchesMacFalseForAWrongKey() throws Exception {
        PKIMessage message = macMessage(SECRET);

        assertFalse(ProtectionMacValidator.matchesMac(message, "wrong".getBytes(StandardCharsets.UTF_8)));
    }

    private static PKIMessage macMessage(String secret) throws Exception {
        PKIBody body = CmpTestUtil.createRevocationBody(BigInteger.ONE);
        return CmpTestUtil.createMacBasedMessage("0102030405060708", secret, body).toASN1Structure();
    }
}
