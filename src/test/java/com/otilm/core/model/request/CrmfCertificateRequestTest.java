package com.otilm.core.model.request;

import com.otilm.api.exception.CertificateRequestException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CrmfCertificateRequestTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void getPublicKey_rsa_returnsBouncyCastleKey() throws Exception {
        // given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        SubjectPublicKeyInfo rsaKey = SubjectPublicKeyInfo
                .getInstance(generator.generateKeyPair().getPublic().getEncoded());
        CrmfCertificateRequest request = toRequest(templateWithSubject().setPublicKey(rsaKey));

        // when
        PublicKey publicKey = request.getPublicKey();

        // then
        assertThat(publicKey).isInstanceOf(BCRSAPublicKey.class);
    }

    @Test
    void getPublicKey_withoutKeyInTemplate_throwsCertificateRequestException() throws Exception {
        // given
        CrmfCertificateRequest request = toRequest(templateWithSubject());

        // when / then
        assertThatThrownBy(request::getPublicKey)
                .isInstanceOf(CertificateRequestException.class)
                .hasMessage("Cannot get public key from certificate request.")
                .hasNoCause();
    }

    @Test
    void getPublicKey_withUnknownKeyAlgorithm_throwsCertificateRequestException() throws Exception {
        // given
        SubjectPublicKeyInfo unknownAlgorithmKey = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")), new byte[]{1, 2, 3});
        CrmfCertificateRequest request = toRequest(templateWithSubject().setPublicKey(unknownAlgorithmKey));

        // when / then
        assertThatThrownBy(request::getPublicKey)
                .isInstanceOf(CertificateRequestException.class)
                .hasMessage("Cannot get public key from certificate request.")
                .hasCauseInstanceOf(NoSuchAlgorithmException.class);
    }

    private static CertificateRequestMessageBuilder templateWithSubject() {
        CertificateRequestMessageBuilder builder = new CertificateRequestMessageBuilder(BigInteger.ONE);
        builder.setSubject(new X500Name("CN=subject"));
        return builder;
    }

    private static CrmfCertificateRequest toRequest(CertificateRequestMessageBuilder builder) throws Exception {
        byte[] encoded = new CertReqMessages(builder.build().toASN1Structure()).getEncoded();
        return new CrmfCertificateRequest(encoded);
    }
}
