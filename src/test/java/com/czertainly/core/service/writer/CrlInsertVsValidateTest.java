package com.czertainly.core.service.writer;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.dao.entity.Crl;
import com.czertainly.core.dao.repository.CrlRepository;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.service.CrlService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CzertainlyX500NameStyle;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrlInsertVsValidateTest extends BaseSpringBootTest {

    @Autowired
    private CrlService crlService;

    @Autowired
    private CrlRepository crlRepository;

    private WireMockServer crlServer;
    private X509Certificate caCert;
    private X509Certificate eeCert;

    @BeforeEach
    void setup() throws Exception {
        crlServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        crlServer.start();
        String crlUrl = "http://localhost:" + crlServer.port() + "/crl/ca.crl";

        KeyPair caKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        caCert = CertificateGeneratorHelper.generateCACertificate(caKeyPair, "CN=CrlRaceCa-" + System.nanoTime());

        KeyPair eeKeyPair = generateRsaKeyPair();
        eeCert = generateEndEntityCertificateWithCdp(caKeyPair, caCert, eeKeyPair, "CN=CrlRaceEE-" + System.nanoTime(), crlUrl);

        X509CRL crl = generateEmptyCrl(caCert, caKeyPair.getPrivate());
        crlServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/crl/ca.crl"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/pkix-crl")
                        .withBody(crl.getEncoded())
                        .withFixedDelay(500)));
    }

    @AfterEach
    void tearDown() {
        if (crlServer != null && crlServer.isRunning()) {
            crlServer.stop();
        }
    }

    @Test
    void parallelGetCurrentCrlCallsResultInExactlyOneRow() throws Exception {
        String issuerDn = X500Name.getInstance(new CzertainlyX500NameStyle(true),
                eeCert.getIssuerX500Principal().getEncoded()).toString();
        String issuerSerial = caCert.getSerialNumber().toString(16);

        // Pre-condition: no CRL row yet for this issuer.
        assertNull(crlRepository.findByIssuerDnAndSerialNumber(issuerDn, issuerSerial).orElse(null),
                "fixture must start with no CRL row for the test issuer");

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch fire = new CountDownLatch(1);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        AtomicReference<Throwable> err1 = new AtomicReference<>();
        AtomicReference<Throwable> err2 = new AtomicReference<>();

        Future<?> f1 = exec.submit(() -> raceWorker(ready, fire, err1));
        Future<?> f2 = exec.submit(() -> raceWorker(ready, fire, err2));

        assertTrue(ready.await(5, TimeUnit.SECONDS), "race workers must signal readiness");
        fire.countDown();

        f1.get(20, TimeUnit.SECONDS);
        f2.get(20, TimeUnit.SECONDS);
        exec.shutdownNow();

        assertNull(err1.get(), "race worker 1 must not throw: " + err1.get());
        assertNull(err2.get(), "race worker 2 must not throw: " + err2.get());

        List<com.czertainly.core.dao.entity.Crl> rows = crlRepository.findAll();
        long matchingRows = rows.stream()
                .filter(c -> issuerDn.equals(c.getIssuerDn()) && issuerSerial.equals(c.getSerialNumber()))
                .count();
        assertEquals(1L, matchingRows,
                "exactly one CRL row must exist for the issuer — ON CONFLICT (issuer_dn, serial_number) DO NOTHING "
                        + "ensures the second insertWithIssuerConflictResolve is a no-op.");

        Crl winningRow = crlRepository.findByIssuerDnAndSerialNumber(issuerDn, issuerSerial).orElseThrow();
        assertNotNull(winningRow.getCrlNumber(), "crl_number must be set on the winning row");
        assertNotNull(winningRow.getNextUpdate(), "next_update must be set on the winning row");
    }

    private void raceWorker(CountDownLatch ready, CountDownLatch fire, AtomicReference<Throwable> err) {
        try {
            ready.countDown();
            fire.await();
            crlService.getCurrentCrl(eeCert, caCert);
        } catch (Throwable t) {
            err.set(t);
        }
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static X509Certificate generateEndEntityCertificateWithCdp(
            KeyPair caKeyPair, X509Certificate caCert, KeyPair eeKeyPair, String subjectDn, String crlUrl) throws Exception {
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.nanoTime());
        Date start = new Date();
        Date end = new Date(System.currentTimeMillis() + 365L * 86400000L);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, start, end, subject, eeKeyPair.getPublic());
        DistributionPoint[] dps = new DistributionPoint[]{
                new DistributionPoint(
                        new DistributionPointName(new GeneralNames(
                                new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl)))),
                        null, null)
        };
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(dps));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(builder.build(signer));
    }

    private static X509CRL generateEmptyCrl(X509Certificate caCert, PrivateKey caKey) throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()),
                new Date());
        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 7L * 86400000L));
        crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(caKey);
        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlBuilder.build(signer));
    }
}
