package com.otilm.core.service.writer;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.CertificateChainService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ServeEventListener;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * <p>Verifies two invariants that must hold for the certificate chain code:
 * <ol>
 * <li><b>No row lock held across AIA HTTP.</b> While the chain bean is in the middle of an AIA-issuer download,
 * a competing UPDATE to the same certificate row must return promptly — proving that the chain bean does not keep
 * a transaction open across the HTTP call.</li>
 * <li><b>No lost update from a stale detached-entity merge.</b> The chain bean's writes go through
 * {@link CertificateChainWriter}, which issues targeted {@code @Modifying} UPDATEs that touch only the issuer columns.
 * A concurrent write to a different column (e.g. {@code state}) must survive the chain bean's later commit.</li>
 * </ol>
 *
 * <p>The test does not extend any class-level {@code @Transactional} — fixtures must be committed before the background
 * and foreground threads run, otherwise neither thread would see them (each thread runs in its own JDBC connection).</p>
 */
class CertificateChainWriteVsRevokeTest extends BaseSpringBootTest {

    @Autowired
    private CertificateChainService chainService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private WireMockServer aiaServer;
    private UUID eeCertUuid;
    private CountDownLatch aiaRequestReceived;

    @BeforeEach
    void setupAiaScenario() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(getAuthentication());

        aiaRequestReceived = new CountDownLatch(1);
        ServeEventListener aiaListener = new ServeEventListener() {
            @Override
            public void afterMatch(ServeEvent serveEvent, Parameters parameters) {
                if (serveEvent.getRequest().getUrl().endsWith("/aia/ca.cer")) {
                    aiaRequestReceived.countDown();
                }
            }

            @Override
            public String getName() {
                return "aiaRequestReceivedListener";
            }
        };
        aiaServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort().extensions(aiaListener));
        aiaServer.start();
        String caIssuersUrl = "http://localhost:" + aiaServer.port() + "/aia/ca.cer";

        // Real CA + EE pair. The EE certificate's AIA caIssuers URL points at WireMock.
        KeyPair caKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate caX509 = CertificateGeneratorHelper.generateCACertificate(
                caKeyPair, "CN=ChainRaceCa");

        KeyPair eeKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate eeX509 = CertificateGeneratorHelper.generateEndEntityCertificateWithCaIssuers(
                caKeyPair, caX509, eeKeyPair, "CN=ChainRaceEE", caIssuersUrl);

        // Persist the EE cert with issuer fields null so chain reconstruction must resolve the issuer.
        eeCertUuid = persistCertificate(eeX509, CertificateState.ISSUED).getUuid();

        // WireMock returns the CA cert (DER) with a 500 ms delay — enough for the foreground/ UPDATE to race the background HTTP wait.
        aiaServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/aia/ca.cer"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/pkix-cert")
                        .withBody(caX509.getEncoded())
                        .withFixedDelay(500)));
    }

    @AfterEach
    void teardown() {
        if (aiaServer != null && aiaServer.isRunning()) {
            aiaServer.stop();
        }
        SecurityContextHolder.clearContext();
    }

    @Test
    void chain_write_does_not_block_or_lose_competing_state_update() throws Exception {
        Certificate eeCert = certificateRepository.findByUuid(eeCertUuid).orElseThrow();

        // ----- Background: chain reconstruction (slow AIA path) -----
        SecurityContext bgContext = SecurityContextHolder.getContext();
        ExecutorService exec = Executors.newSingleThreadExecutor();
        AtomicReference<Throwable> bgError = new AtomicReference<>();
        Future<?> bgFuture = exec.submit(() -> {
            SecurityContextHolder.setContext(bgContext);
            try {
                chainService.updateCertificateChain(eeCert);
            } catch (Throwable t) {
                bgError.set(t);
            } finally {
                SecurityContextHolder.clearContext();
            }
        });

        assertTrue(aiaRequestReceived.await(10, TimeUnit.SECONDS),
                "AIA server did not receive /aia/ca.cer request within 10 s");

        // ----- Foreground: competing state update to the SAME row -----
        // Direct JDBC bypasses JPA so this models any external-actor write (a revoke while validation+chain are in flight).
        long fgStart = System.currentTimeMillis();
        int updated = jdbcTemplate.update(
                "UPDATE core.certificate SET state = ?, i_upd = CURRENT_TIMESTAMP WHERE uuid = ?",
                CertificateState.PENDING_REVOKE.name(), eeCertUuid);
        long fgElapsedMs = System.currentTimeMillis() - fgStart;
        assertEquals(1, updated, "foreground UPDATE must affect exactly one row");

        // Invariant 1: the chain bean does not hold a row lock across the AIA HTTP.
        assertTrue(fgElapsedMs < 2_000,
                "Foreground UPDATE took " + fgElapsedMs + " ms — chain bean appears to hold "
                        + "a row lock across AIA HTTP. Expected < 2 s.");

        // ----- Drain background -----
        try {
            bgFuture.get(15, TimeUnit.SECONDS);
        } finally {
            exec.shutdownNow();
        }
        assertNull(bgError.get(), "background chain reconstruction must not throw: " + bgError.get());

        // ----- Invariant 2: the chain bean's targeted UPDATE did not clobber state -----
        String finalState = jdbcTemplate.queryForObject(
                "SELECT state FROM core.certificate WHERE uuid = ?", String.class, eeCertUuid);
        assertEquals(CertificateState.PENDING_REVOKE.name(), finalState,
                "Foreground state update must survive the chain bean's later writer call. "
                        + "If state regresses to ISSUED the chain code did a full-entity merge "
                        + "instead of a targeted UPDATE — the lost-update regression.");

        // Sanity: the chain bean did successfully set the issuer reference.
        Certificate reloaded = certificateRepository.findByUuid(eeCertUuid).orElseThrow();
        assertNotNull(reloaded.getIssuerCertificateUuid(),
                "chain reconstruction must have set issuerCertificateUuid via the writer");
    }

    private Certificate persistCertificate(X509Certificate x509, CertificateState state) throws Exception {
        String fingerprint = CertificateUtil.getThumbprint(x509);

        CertificateContent content = new CertificateContent();
        content.setFingerprint(fingerprint);
        content.setContent(Base64.getEncoder().encodeToString(x509.getEncoded()));
        content = certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        CertificateUtil.prepareIssuedCertificate(cert, x509);
        cert.setCertificateContent(content);
        cert.setCertificateContentId(content.getId());
        cert.setIssuerCertificateUuid(null);
        cert.setState(state);
        return certificateRepository.save(cert);
    }
}
