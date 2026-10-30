package com.otilm.core.service.scep.message;

import com.otilm.api.model.core.scep.PkiStatus;
import com.otilm.core.util.CertificateUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies the enveloping mechanism of a SCEP {@code SUCCESS} CertRep is chosen by the recipient key's capability, not
 * fixed to RSA key transport.
 *
 * <p>
 * An EC client key cannot receive an RSA-key-transport envelope; the response must fall back to the RFC 8894 §3.2.2
 * password recipient keyed with the shared challenge password — mirroring the request-decryption path
 * ({@code ScepRequest.decryptData}). RSA recipients must keep using key transport unchanged.
 * </p>
 */
class ScepResponseEnvelopeTest {

    // P-256 self-signed client cert (same test material used by EcdsaCmsMessageTest / CmsMessageTest).
    private static final String EC_CLIENT_CERT_B64 = "MIIB5TCCAYqgAwIBAgIUQWJcNhcZ8rdJ8d+Y0/zjDauIDvAwCgYIKoZIzj0EAwIwNzELMAkGA1UEBhMCSU4xEzARBgNVBAgMClRhbWlsIE5hZHUxEzARBgNVBAcMCkNvaW1iYXRvcmUwHhcNMjMwNDE5MTAxNjI0WhcNMjQwNDE4MTAxNjI0WjA3MQswCQYDVQQGEwJJTjETMBEGA1UECAwKVGFtaWwgTmFkdTETMBEGA1UEBwwKQ29pbWJhdG9yZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1ILz/GLiGtx9JIoFesLv6ssTrBr5W1c+FUuCKUGjvZpM8l5wAbC9TJaYwcA3B45iuTAzmTTOoPCwrr/ALGhoyjdDByMB0GA1UdDgQWBBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAfBgNVHSMEGDAWgBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAOBgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAoGCCqGSM49BAMCA0kAMEYCIQCUxvkZzxraytwbhhoCafIzHaj62EGVbxW5bUlvLTZPIwIhAJ6eFFyO8f9udwCHUt+4aMQGyBHCISbgvgvejMU6NSZU";

    private static final String CHALLENGE_PASSWORD = "mysecretpassword";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void successResponseToEcRecipient_isDecryptableWithChallengePassword() throws Exception {
        X509Certificate ecClient = CertificateUtil.parseCertificate(EC_CLIENT_CERT_B64);
        ScepResponse response = successResponseFor(ecClient);
        response.setChallengePassword(CHALLENGE_PASSWORD);

        CMSEnvelopedData enveloped = response.buildEnvelopedResponse();

        RecipientInformation recipient = enveloped.getRecipientInfos().getRecipients().iterator().next();
        assertInstanceOf(PasswordRecipientInformation.class, recipient);
        byte[] decrypted = recipient
                .getContent(new JcePasswordEnvelopedRecipient(CHALLENGE_PASSWORD.toCharArray())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME));

        // The enveloped payload is the certs-only degenerate CMS SignedData carrying the issued chain.
        CMSSignedData innerSignedData = new CMSSignedData(decrypted);
        assertFalse(innerSignedData.getCertificates().getMatches(null).isEmpty());
    }

    @Test
    void successResponseToEcRecipient_viaIssuedLeafFallback_usesPasswordRecipient() throws Exception {
        // No recipientKeyInfo on the request: the response envelopes to the issued leaf
        // (certificateChain[0]), which for an EC issuance is an EC key and must still route to the
        // password recipient.
        X509Certificate ecLeaf = CertificateUtil.parseCertificate(EC_CLIENT_CERT_B64);
        ScepResponse response = new ScepResponse();
        response.setPkiStatus(PkiStatus.SUCCESS);
        response.setCertificateChain(List.of(ecLeaf));
        response.setChallengePassword(CHALLENGE_PASSWORD);
        // recipientKeyInfo deliberately left null

        CMSEnvelopedData enveloped = response.buildEnvelopedResponse();

        RecipientInformation recipient = enveloped.getRecipientInfos().getRecipients().iterator().next();
        assertInstanceOf(PasswordRecipientInformation.class, recipient);
        byte[] decrypted = recipient
                .getContent(new JcePasswordEnvelopedRecipient(CHALLENGE_PASSWORD.toCharArray())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME));
        assertFalse(new CMSSignedData(decrypted).getCertificates().getMatches(null).isEmpty());
    }

    @Test
    void successResponseToEcRecipient_withoutChallengePassword_fails() throws Exception {
        X509Certificate ecClient = CertificateUtil.parseCertificate(EC_CLIENT_CERT_B64);
        ScepResponse response = successResponseFor(ecClient);
        // No challenge password configured — an EC recipient has no derivable envelope key.

        assertThrows(CMSException.class, response::buildEnvelopedResponse);
    }

    @Test
    void successResponseToRsaRecipient_usesKeyTransport() throws Exception {
        KeyPair rsaKeyPair = generateRsaKeyPair();
        X509Certificate rsaClient = selfSignedRsaCertificate(rsaKeyPair);
        ScepResponse response = successResponseFor(rsaClient);
        // Deliberately no challenge password: RSA must go through key transport, not the password path.

        CMSEnvelopedData enveloped = response.buildEnvelopedResponse();

        RecipientInformation recipient = enveloped.getRecipientInfos().getRecipients().iterator().next();
        assertInstanceOf(KeyTransRecipientInformation.class, recipient);
        byte[] decrypted = recipient
                .getContent(new JceKeyTransEnvelopedRecipient(rsaKeyPair.getPrivate())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME));

        CMSSignedData innerSignedData = new CMSSignedData(decrypted);
        assertFalse(innerSignedData.getCertificates().getMatches(null).isEmpty());
    }

    @Test
    void successResponseToRsaRecipient_withChallengePassword_stillUsesKeyTransport() throws Exception {
        // An RSA recipient keeps key transport even when a challenge password is available — the
        // password path is only for keys that cannot do key transport.
        KeyPair rsaKeyPair = generateRsaKeyPair();
        X509Certificate rsaClient = selfSignedRsaCertificate(rsaKeyPair);
        ScepResponse response = successResponseFor(rsaClient);
        response.setChallengePassword(CHALLENGE_PASSWORD);

        CMSEnvelopedData enveloped = response.buildEnvelopedResponse();

        RecipientInformation recipient = enveloped.getRecipientInfos().getRecipients().iterator().next();
        assertInstanceOf(KeyTransRecipientInformation.class, recipient);
        byte[] decrypted = recipient
                .getContent(new JceKeyTransEnvelopedRecipient(rsaKeyPair.getPrivate())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME));
        assertFalse(new CMSSignedData(decrypted).getCertificates().getMatches(null).isEmpty());
    }

    private static ScepResponse successResponseFor(X509Certificate recipient) throws Exception {
        ScepResponse response = new ScepResponse();
        response.setPkiStatus(PkiStatus.SUCCESS);
        response.setCertificateChain(List.of(recipient));
        response.setRecipientKeyInfo(recipient.getEncoded());
        return response;
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate selfSignedRsaCertificate(KeyPair keyPair) throws Exception {
        X500Name dn = new X500Name("CN=rsa-test-client");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn,
                BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, dn, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
