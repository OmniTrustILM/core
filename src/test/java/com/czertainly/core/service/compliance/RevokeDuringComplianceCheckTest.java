package com.czertainly.core.service.compliance;

import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.service.handler.CertificateHandler;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.CertificateUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Verifies that certificate revocation and certificate X.509 validation interleave cleanly when they run concurrently
 * against the same certificate row: a revoke issued while a validation is in progress completes promptly and the resulting
 * {@code PENDING_REVOKE} state survives the validation finishing.
 */
class RevokeDuringComplianceCheckTest extends BaseComplianceTest {

    @Autowired
    private ClientOperationService clientOperationService;

    @Autowired
    private CertificateHandler certificateHandler;

    private WireMockServer ocspServer;
    private UUID eeCertUuid;

    @BeforeEach
    void setUpRowLock() throws Exception {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        SecurityContextHolder.getContext().setAuthentication(getAuthentication());

        // Dedicated WireMock server for OCSP.
        ocspServer = new WireMockServer(0);
        ocspServer.start();

        String ocspUrl = "http://localhost:" + ocspServer.port() + "/ocsp";

        // Generate a real CA + end-entity cert pair. The end-entity cert embeds the WireMock URL as its OCSP AIA
        // so X509CertificateValidator's OCSP check makes an HTTP call to WireMock, keeping the validation transaction open.
        CertificateGeneratorHelper.CertificateChainInfo chain =
                CertificateGeneratorHelper.generateCertificateWithIssuer(
                        KeyAlgorithm.RSA, "CN=RowLock-CA", "CN=RowLock-EE", ocspUrl);

        // CA cert in DB: its subjectDnNormalized must match the EE cert's issuerDnNormalized.
        storeCertificate(chain.getCaCertificate(), null);

        // EE cert linked to an RA profile that has an authority connector (required for the revoke HTTP call).
        eeCertUuid = storeCertificate(chain.getEndEntityCertificate(), unassociatedRaProfileUuid).getUuid();

        // OCSP stub: a 3-second fixed delay models a slow OCSP responder, so the validation's external
        // call is still in flight while the concurrent revoke runs.
        ocspServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/ocsp"))
                .willReturn(WireMock.aResponse()
                        .withStatus(500)
                        .withFixedDelay(3_000)));

        // Authority connector: 202 Accepted causes revokeCertificateAction() to perform the local PENDING_REVOKE transition.
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching(
                        "/v2/authorityProvider/authorities/[^/]+/certificates/revoke"))
                .willReturn(WireMock.aResponse().withStatus(202)));
    }

    private Certificate storeCertificate(X509Certificate x509, UUID raProfileUuid) throws Exception {
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
        if (raProfileUuid != null) {
            cert.setRaProfileUuid(raProfileUuid);
        }
        return certificateRepository.save(cert);
    }

    @AfterEach
    void tearDown() {
        if (ocspServer != null && ocspServer.isRunning()) {
            ocspServer.stop();
        }
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }

    /**
     * Verifies that a revoke issued while certificate X.509 validation is in progress completes
     * promptly and that the certificate row reflects the {@code PENDING_REVOKE} transition once the
     * concurrent validation finishes.
     *
     * <p>Timeline:
     * <ol>
     *   <li>Background thread: {@code validate()} calls {@code completeCertificateChain()} →
     *       {@code updateCertificateChain()} → {@code chainWriter.applyIssuerReference(eeCert)}, whose
     *       UPDATE commits in its own micro-transaction and releases the certificate row lock before
     *       the thread POSTs to the WireMock OCSP endpoint (3 s fixed delay).</li>
     *   <li>Main thread (500 ms into step 1): {@code revokeCertificateAction()} calls the authority
     *       connector (202 → OK) then performs the PENDING_REVOKE transition UPDATE, which proceeds
     *       without waiting on the validation thread and returns promptly.</li>
     * </ol>
     *
     * <p>The issuer-reference UPDATE having committed before any external HTTP call is what lets the
     * concurrent revoke complete without contending for the row lock during the OCSP call.
     */
    @Test
    void revokeDuringValidationCompletesPromptlyAndPreservesRevokedState() throws Exception {
        Certificate certWithAssociations = certificateRepository
                .findAllWithAssociationsByUuidIn(List.of(eeCertUuid))
                .getFirst();

        // Step 1: start validation in a background thread. The issuer-reference UPDATE (via
        // updateCertificateChain → applyIssuerReference) commits and releases the row lock, then the
        // thread makes the OCSP HTTP call (3 s WireMock fixed delay).
        ExecutorService exec = Executors.newSingleThreadExecutor();
        Future<?> validationFuture = exec.submit(() ->
                certificateHandler.validate(certWithAssociations));

        // Allow the background thread to pass through updateCertificateChain() and enter the OCSP
        // HTTP call. 500 ms is well within the 3 s OCSP window.
        Thread.sleep(500);

        // Step 2: revoke — connector returns 202, which routes into the PENDING_REVOKE transition.
        // This UPDATE proceeds independently of the in-flight validation and completes promptly.
        ClientCertificateRevocationDto revokeRequest = new ClientCertificateRevocationDto();
        revokeRequest.setAttributes(List.of());
        revokeRequest.setDestroyKey(false);

        long revokeStart = System.currentTimeMillis();
        clientOperationService.revokeCertificateAction(eeCertUuid, revokeRequest, true);
        long revokeElapsedMs = System.currentTimeMillis() - revokeStart;

        validationFuture.get(10, TimeUnit.SECONDS);
        exec.shutdown();

        Assertions.assertTrue(
                revokeElapsedMs < 2_000,
                "revokeCertificateAction took " + revokeElapsedMs + " ms — a revoke issued during an "
                + "in-progress validation is expected to complete in under 2 s, independently of the "
                + "validation's external OCSP call.");

        Certificate finalCert = certificateRepository.findByUuid(eeCertUuid).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_REVOKE, finalCert.getState(),
                "Certificate state must remain PENDING_REVOKE after the concurrent validation "
                + "completes, since the validation thread updates only the validation columns.");
    }
}
