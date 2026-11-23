package com.otilm.core.util;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KeySizeUtilTest {

    @Test
    void sizesAnEcKeyByItsField_whenTheCurveOrderOutgrowsTheField() throws Exception {
        // given
        var generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec("secp224k1"));
        var publicKey = generator.generateKeyPair().getPublic();

        // when
        int length = KeySizeUtil.getKeyLength(publicKey);

        // then
        assertThat(length).isEqualTo(224);
    }

    @Test
    void sizesAnEcKeyByItsField_whenItsOidIsOutsideCoresTable() throws Exception {
        // given
        var generator = KeyPairGenerator.getInstance("ECGOST3410", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec("GostR3410-2001-CryptoPro-A"));
        var gostPublicKey = generator.generateKeyPair().getPublic();

        // when
        int length = KeySizeUtil.getKeyLength(gostPublicKey);

        // then
        assertThat(length).isEqualTo(256);
    }
}
