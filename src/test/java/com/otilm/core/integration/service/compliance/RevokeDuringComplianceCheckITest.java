package com.otilm.core.integration.service.compliance;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.compliance.BaseComplianceTest;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.CertificateUtil;
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

import static org.awaitility.Awaitility.await;

/**
 * Verifies that certificate revocation and certificate X.509 validation interleave cleanly when they run concurrently
 * against the same certificate row: a revoke issued while a validation is in progress completes promptly and the resulting
 * {@code PENDING_REVOKE} state survives the validation finishing.
 */
class RevokeDuringComplianceCheckITest extends BaseComplianceTest {

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private CertificateHandler certificateHandler;

    private WireMockServer ocspServer;
    private UUID eeCertUuid;

    @BeforeEach
    void setUpRowLock() throws Exception {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        SecurityContextHolder.getContext().setAuthentication(getAuthentication());

        ocspServer = new WireMockServer(0);
        ocspServer.start();

        String ocspUrl = "http://localhost:" + ocspServer.port() + "/ocsp";

        // The EE cert embeds this WireMock URL as its OCSP AIA, so X509CertificateValidator's OCSP
        // check makes a real HTTP call to WireMock during validate().
        CertificateGeneratorHelper.CertificateChainInfo chain =
                CertificateGeneratorHelper.generateCertificateWithIssuer(
                        KeyAlgorithm.RSA, "CN=RowLock-CA", "CN=RowLock-EE", ocspUrl);

        // The CA must be in the DB so chain completion links EE→CA (subjectDnNormalized matches the
        // EE's issuerDnNormalized); the EE needs an RA profile with an authority connector to revoke.
        storeCertificate(chain.getCaCertificate(), null);
        eeCertUuid = storeCertificate(chain.getEndEntityCertificate(), unassociatedRaProfileUuid).getUuid();

        // 3 s fixed delay models a slow OCSP responder, so the validation's external call is still in
        // flight while the concurrent revoke runs (the window the test exercises).
        ocspServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/ocsp"))
                .willReturn(WireMock.aResponse()
                        .withStatus(500)
                        .withFixedDelay(3_000)));

        // 202 Accepted routes revokeCertificateAction() into the local PENDING_REVOKE transition.
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
    @Override
    protected void tearDown() {
        if (ocspServer != null && ocspServer.isRunning()) {
            ocspServer.stop();
        }
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
        super.tearDown();
    }

    /**
     * Verifies that a revoke issued while certificate X.509 validation is in progress completes
     * promptly and that the certificate row reflects the {@code PENDING_REVOKE} transition once the
     * concurrent validation finishes.
     *
     * <p>Because {@code validate()} commits its issuer-reference write in its own micro-transaction
     * before making the OCSP HTTP call, it holds no row lock during that call — so the concurrent
     * revoke must not contend for the lock and must return without waiting on the slow OCSP response.
     */
    @Test
    void revokeDuringValidationCompletesPromptlyAndPreservesRevokedState() throws Exception {
        Certificate certWithAssociations = certificateRepository
                .findAllWithAssociationsByUuidIn(List.of(eeCertUuid))
                .getFirst();

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<?> validationFuture = exec.submit(() ->
                    certificateHandler.validate(certWithAssociations));

            // Proceed only once the validation thread's OCSP request has actually reached WireMock and is
            // blocking on the 3 s delay. Polling the request journal (rather than a fixed sleep) makes the
            // overlap deterministic: the revoke below is guaranteed to run while the OCSP call is in flight.
            awaitOcspRequestInFlight();

            ClientCertificateRevocationDto revokeRequest = new ClientCertificateRevocationDto();
            revokeRequest.setAttributes(List.of());
            revokeRequest.setDestroyKey(false);

            long revokeStart = System.currentTimeMillis();
            clientOperationService.revokeCertificateAction(eeCertUuid, revokeRequest, true);
            long revokeElapsedMs = System.currentTimeMillis() - revokeStart;

            validationFuture.get(10, TimeUnit.SECONDS);

            Assertions.assertTrue(
                    revokeElapsedMs < 2_000,
                    "revokeCertificateAction took " + revokeElapsedMs + " ms — with the OCSP call confirmed "
                    + "in flight, a revoke is expected to complete in under 2 s; a duration near the 3 s OCSP "
                    + "delay would indicate it is contending for the certificate row lock.");

            Certificate finalCert = certificateRepository.findByUuid(eeCertUuid).orElseThrow();
            Assertions.assertEquals(CertificateState.PENDING_REVOKE, finalCert.getState(),
                    "Certificate state must remain PENDING_REVOKE after the concurrent validation "
                    + "completes, since the validation thread updates only the validation columns.");
        } finally {
            exec.shutdownNow();
        }
    }

    /**
     * Blocks until the OCSP endpoint has received at least one request, i.e. the background
     * validation thread is parked on WireMock's fixed delay. The request journal is populated on
     * receipt, before the delayed response is served, so this returns while the call is still open.
     */
    private void awaitOcspRequestInFlight() {
        await()
                .atMost(3, TimeUnit.SECONDS)
                .pollInterval(20, TimeUnit.MILLISECONDS)
                .until(() -> ocspServer.countRequestsMatching(
                        WireMock.postRequestedFor(WireMock.urlPathEqualTo("/ocsp")).build()).getCount() > 0);
    }
}
