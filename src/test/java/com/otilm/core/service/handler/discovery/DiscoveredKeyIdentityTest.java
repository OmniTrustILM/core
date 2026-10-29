package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static org.assertj.core.api.Assertions.assertThat;

class DiscoveredKeyIdentityTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void publicKeyOf_rsa_returnsBouncyCastleKey() throws Exception {
        // given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String spki = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        DiscoveredKeyDto key = aPublicKey().withSpki(spki).build();

        // when
        PublicKey publicKey = DiscoveredKeyIdentity.publicKeyOf(key);

        // then
        assertThat(publicKey).isInstanceOf(BCRSAPublicKey.class);
    }
}
