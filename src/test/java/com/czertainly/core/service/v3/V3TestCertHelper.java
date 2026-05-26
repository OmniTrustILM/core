package com.czertainly.core.service.v3;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Minimal helper to produce test PKI artifacts without using real keys.
 * Only used in IT tests to supply valid DER bytes where the parser requires them.
 */
final class V3TestCertHelper {

    private V3TestCertHelper() {}

    static byte[] generateSelfSignedCsrDer() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();

        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=v3-test"), kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));
        return csr.getEncoded();
    }
}
