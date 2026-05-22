package com.czertainly.core.service.chain;

import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.service.CertificateChainService;
import com.czertainly.core.service.writer.CertificateChainWriter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Headline regression test for the PR1 chain-bean refactor.
 *
 * <p>Verifies two invariants that must hold for the refactored chain code:
 * <ol>
 *   <li><b>No row lock held across AIA HTTP.</b> While the chain bean is in the
 *       middle of an AIA-issuer download (3 s WireMock fixed delay), a competing
 *       UPDATE to the same certificate row must return promptly — proving that
 *       the chain bean does not keep a transaction open across the HTTP call.</li>
 *   <li><b>No lost update from a stale detached-entity merge.</b> The chain
 *       bean's writes go through {@link CertificateChainWriter}, which issues
 *       targeted {@code @Modifying} UPDATEs that touch only the issuer columns.
 *       A concurrent write to a different column (e.g. {@code state}) must
 *       survive the chain bean's later commit. The old {@code save(detachedEntity)}
 *       path would have re-merged the in-memory entity and clobbered the
 *       competing state change.</li>
 * </ol>
 *
 * <p>The test is intentionally constructed to force the AIA branch: the EE
 * certificate is uploaded with its issuer fields null, and the CA is NOT
 * persisted in the DB, so {@code findBySubjectDnNormalized} returns nothing and
 * chain reconstruction falls through to the AIA-download path.</p>
 *
 * <p>The test does not extend any class-level {@code @Transactional} — fixtures
 * must be committed before the background and foreground threads run, otherwise
 * neither thread would see them (each thread runs in its own JDBC connection).</p>
 */
class ChainWriteVsRevokeTest extends BaseSpringBootTest {

    @Autowired
    private CertificateChainService chainService;

    @Autowired
    private CertificateChainWriter chainWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private WireMockServer aiaServer;
    private UUID eeCertUuid;

    @BeforeEach
    void setupAiaScenario() throws Exception {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        SecurityContextHolder.getContext().setAuthentication(getAuthentication());

        aiaServer = new WireMockServer(0);
        aiaServer.start();
        String caIssuersUrl = "http://localhost:" + aiaServer.port() + "/aia/ca.cer";

        // Real CA + EE pair. The EE certificate's AIA caIssuers URL points at WireMock.
        KeyPair caKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate caX509 = CertificateGeneratorHelper.generateCACertificate(
                caKeyPair, "CN=ChainRaceCa");

        KeyPair eeKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate eeX509 = CertificateGeneratorHelper.generateEndEntityCertificateWithCaIssuers(
                caKeyPair, caX509, eeKeyPair, "CN=ChainRaceEE", caIssuersUrl);

        // Persist the EE cert with issuer fields null so chain reconstruction must
        // resolve the issuer (and, because the CA is NOT in the DB, must fall through
        // to the AIA branch — which is the slow HTTP path we want to race against).
        eeCertUuid = persistCertificate(eeX509, CertificateState.ISSUED).getUuid();

        // WireMock returns the CA cert (DER) with a 3 s delay so the AIA download
        // takes long enough for the foreground thread to issue its competing UPDATE
        // while the background thread is still waiting on HTTP.
        aiaServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/aia/ca.cer"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/pkix-cert")
                        .withBody(caX509.getEncoded())
                        .withFixedDelay(3_000)));
    }

    @AfterEach
    void teardown() {
        if (aiaServer != null && aiaServer.isRunning()) {
            aiaServer.stop();
        }
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
        // BaseSpringBootTest.truncateTables() runs before each test; no manual cleanup needed.
    }

    @Test
    void chain_write_does_not_block_or_lose_competing_state_update() throws Exception {
        Certificate eeCert = certificateRepository.findByUuid(eeCertUuid).orElseThrow();

        // ----- Background: chain reconstruction (slow AIA path) -----
        ExecutorService exec = Executors.newSingleThreadExecutor();
        AtomicReference<Throwable> bgError = new AtomicReference<>();
        Future<?> bgFuture = exec.submit(() -> {
            try {
                chainService.updateCertificateChain(eeCert);
            } catch (Throwable t) {
                bgError.set(t);
            }
        });

        // Allow the background thread to parse the cert, query the inventory (no match),
        // and enter the AIA download. 500 ms is well within the 3 s WireMock window.
        Thread.sleep(500);

        // ----- Foreground: competing state update to the SAME row -----
        // Direct JDBC bypasses JPA so this models any external-actor write (e.g. a
        // revoke that lands while validation+chain are in flight) — and confirms the
        // chain bean's later UPDATE on the issuer columns does not clobber state.
        long fgStart = System.currentTimeMillis();
        int updated = jdbcTemplate.update(
                "UPDATE core.certificate SET state = ?, i_upd = CURRENT_TIMESTAMP WHERE uuid = ?",
                CertificateState.PENDING_REVOKE.name(), eeCertUuid);
        long fgElapsedMs = System.currentTimeMillis() - fgStart;
        assertEquals(1, updated, "foreground UPDATE must affect exactly one row");

        // Invariant 1: the chain bean does not hold a row lock across the AIA HTTP.
        // Without the fix, this UPDATE would queue behind the chain bean's pessimistic
        // lock until the WireMock 3 s delay elapsed.
        assertTrue(fgElapsedMs < 2_000,
                "Foreground UPDATE took " + fgElapsedMs + " ms — chain bean appears to hold "
                        + "a row lock across AIA HTTP. Expected < 2 s.");

        // ----- Drain background -----
        bgFuture.get(15, TimeUnit.SECONDS);
        exec.shutdown();
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
