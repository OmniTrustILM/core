package com.otilm.core.key.normalization;

import java.security.KeyPair;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TraditionalKeyTest {

    @BeforeAll
    static void providers() {
        KeyFiles.registerProviders();
    }

    @Test
    void privateKeyInfo_carriesTheKeyIntoPkcs8AndOverwritesTheBytesItReads() throws Exception {
        // given
        KeyPair rsa = KeyFiles.rsa();
        byte[] traditional = PrivateKeyInfo
                .getInstance(KeyFiles.pkcs8(rsa))
                .parsePrivateKey()
                .toASN1Primitive()
                .getEncoded();

        // when
        PrivateKeyInfo privateKeyInfo = TraditionalKey.RSA.privateKeyInfo(traditional);

        // then
        assertThat(privateKeyInfo.getEncoded()).isEqualTo(rsa.getPrivate().getEncoded());
        assertThat(traditional).containsOnly((byte) 0);
    }
}
