package com.otilm.core.model.request;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Pkcs10CertificateRequestTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void getPublicKey_rsa_returnsBouncyCastleKey() throws Exception {
        // given
        KeyPair keyPair = rsaKeyPair();
        Pkcs10CertificateRequest request = toRequest(requestFor(keyPair).build(signerOf(keyPair, "SHA256withRSA")));

        // when
        PublicKey publicKey = request.getPublicKey();

        // then
        assertThat(publicKey).isInstanceOf(BCRSAPublicKey.class);
    }

    @Test
    void getPublicKey_ec_returnsBouncyCastleKeyWithTheJdkName() throws Exception {
        // given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        Pkcs10CertificateRequest request = toRequest(requestFor(keyPair).build(signerOf(keyPair, "SHA256withECDSA")));

        // when
        PublicKey publicKey = request.getPublicKey();

        // then
        assertThat(publicKey).isInstanceOf(BCECPublicKey.class);
        assertThat(publicKey.getAlgorithm()).isEqualTo(keyPair.getPublic().getAlgorithm());
    }

    @Test
    void getAltPublicKey_rsa_returnsBouncyCastleKey() throws Exception {
        // given
        KeyPair keyPair = rsaKeyPair();
        KeyPair altKeyPair = rsaKeyPair();
        PKCS10CertificationRequest hybridRequest = requestFor(keyPair)
                .build(signerOf(keyPair, "SHA256withRSA"), altKeyPair.getPublic(),
                        signerOf(altKeyPair, "SHA256withRSA"));
        Pkcs10CertificateRequest request = toRequest(hybridRequest);

        // when
        PublicKey altPublicKey = request.getAltPublicKey();

        // then
        assertThat(altPublicKey).isInstanceOf(BCRSAPublicKey.class);
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static JcaPKCS10CertificationRequestBuilder requestFor(KeyPair keyPair) {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=subject"), keyPair.getPublic());
    }

    private static ContentSigner signerOf(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        return new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
    }

    private static Pkcs10CertificateRequest toRequest(PKCS10CertificationRequest request) throws Exception {
        return new Pkcs10CertificateRequest(request.getEncoded());
    }
}
