package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.service.scep.message.ScepRequest;
import com.otilm.core.util.CertificateUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the pre-issuance envelope check {@link ScepServiceImpl#verifyResponseEnvelopable}. A non-RSA client
 * key can only receive its issued certificate via the RFC 8894 password recipient, so a profile with no challenge
 * password must reject the enrollment before any certificate is committed — rather than issuing a certificate the
 * client could never retrieve.
 */
class ScepServiceImplEnvelopePreflightTest {

    // P-256 self-signed cert (same test material as ScepResponseEnvelopeTest).
    private static final String EC_CERT_B64 = "MIIB5TCCAYqgAwIBAgIUQWJcNhcZ8rdJ8d+Y0/zjDauIDvAwCgYIKoZIzj0EAwIwNzELMAkGA1UEBhMCSU4xEzARBgNVBAgMClRhbWlsIE5hZHUxEzARBgNVBAcMCkNvaW1iYXRvcmUwHhcNMjMwNDE5MTAxNjI0WhcNMjQwNDE4MTAxNjI0WjA3MQswCQYDVQQGEwJJTjETMBEGA1UECAwKVGFtaWwgTmFkdTETMBEGA1UEBwwKQ29pbWJhdG9yZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1ILz/GLiGtx9JIoFesLv6ssTrBr5W1c+FUuCKUGjvZpM8l5wAbC9TJaYwcA3B45iuTAzmTTOoPCwrr/ALGhoyjdDByMB0GA1UdDgQWBBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAfBgNVHSMEGDAWgBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAOBgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAoGCCqGSM49BAMCA0kAMEYCIQCUxvkZzxraytwbhhoCafIzHaj62EGVbxW5bUlvLTZPIwIhAJ6eFFyO8f9udwCHUt+4aMQGyBHCISbgvgvejMU6NSZU";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private ScepServiceImpl service;
    private ScepProfile profile;

    @BeforeEach
    void setUp() {
        service = new ScepServiceImpl();
        profile = mock(ScepProfile.class);
        ReflectionTestUtils.setField(service, "scepProfile", profile);
    }

    @Test
    void ecKeyWithoutChallengePassword_rejectsWithBadAlg() throws Exception {
        when(profile.getChallengePassword()).thenReturn(null);
        ScepRequest request = requestSignedBy(CertificateUtil.parseCertificate(EC_CERT_B64));

        ScepException thrown = assertThrows(ScepException.class, () -> service.verifyResponseEnvelopable(request));
        assertEquals(FailInfo.BAD_ALG, thrown.getFailInfo());
    }

    @Test
    void ecKeyWithChallengePassword_passes() throws Exception {
        when(profile.getChallengePassword()).thenReturn("mysecretpassword");
        ScepRequest request = requestSignedBy(CertificateUtil.parseCertificate(EC_CERT_B64));

        assertDoesNotThrow(() -> service.verifyResponseEnvelopable(request));
    }

    @Test
    void rsaKeyWithoutChallengePassword_passes() throws Exception {
        when(profile.getChallengePassword()).thenReturn(null);
        ScepRequest request = requestSignedBy(selfSignedRsaCertificate());

        assertDoesNotThrow(() -> service.verifyResponseEnvelopable(request));
    }

    @Test
    void noSignerCertificate_passes() {
        ScepRequest request = requestSignedBy(null);

        assertDoesNotThrow(() -> service.verifyResponseEnvelopable(request));
    }

    private static ScepRequest requestSignedBy(X509Certificate signerCertificate) {
        ScepRequest request = mock(ScepRequest.class);
        when(request.getSignerCertificate()).thenReturn(signerCertificate);
        return request;
    }

    private static X509Certificate selfSignedRsaCertificate() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
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
