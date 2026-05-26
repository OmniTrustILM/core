package com.czertainly.core.service.v3;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.messaging.jms.listeners.CertificateStatusPollListener;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.service.handler.authority.CertificateOperation;
import com.czertainly.core.service.v2.ClientOperationService;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Async issue flow: connector returns 202, poll listener drives IN_PROGRESS → COMPLETED → ISSUED.
 *
 * The JmsTemplate is mocked in the "test" profile, so the poll producer sends nothing.
 * The test drives the listener directly by calling {@code processMessage} three times:
 * first two simulate IN_PROGRESS (re-enqueue), third simulates COMPLETED with cert data.
 */
class V3AsyncIssueITest extends BaseV3ITest {

    @Autowired
    @Qualifier("clientOperationServiceImplV2")
    private ClientOperationService clientOperationService;

    @Autowired
    private CertificateStatusPollListener pollListener;

    @Test
    void asyncIssue_inProgressThenCompleted_endsInIssuedState() throws Exception {
        InputStream ks = getClass().getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(ks, "123456".toCharArray());
        X509Certificate x509 = (X509Certificate) keyStore.getCertificate("1");
        String certB64 = Base64.getEncoder().encodeToString(x509.getEncoded());

        // Stub: issue returns 202 Accepted (no cert data)
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody(asyncAcceptedBody())));

        // Stub: poll status — first call IN_PROGRESS, second call IN_PROGRESS, third COMPLETED
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_STATUS_PATH))
                .inScenario("issue-poll")
                .whenScenarioStateIs("Started")
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(statusResponseBody("inProgress")))
                .willSetStateTo("second-poll"));

        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_STATUS_PATH))
                .inScenario("issue-poll")
                .whenScenarioStateIs("second-poll")
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(statusResponseBody("inProgress")))
                .willSetStateTo("third-poll"));

        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_STATUS_PATH))
                .inScenario("issue-poll")
                .whenScenarioStateIs("third-poll")
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(statusResponseBodyWithCert("completed", certB64))));

        // Create cert in REQUESTED state with CSR, then trigger issue action
        String csrB64 = Base64.getEncoder().encodeToString(V3TestCertHelper.generateSelfSignedCsrDer());
        Certificate cert = buildCertInStateWithCsr(CertificateState.REQUESTED, csrB64);

        clientOperationService.issueCertificateAction(cert.getUuid(), true);

        // After 202, cert should be in PENDING_ISSUE
        Certificate afterIssue = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.PENDING_ISSUE, afterIssue.getState(),
                "After 202 from connector, cert must be PENDING_ISSUE");

        // Drive poll: attempt 1 → IN_PROGRESS (re-enqueue)
        CertificateStatusPollMessage msg1 = new CertificateStatusPollMessage(Resource.CERTIFICATE, cert.getUuid(), CertificateOperation.ISSUE, 1);
        pollListener.processMessage(msg1);
        assertEquals(CertificateState.PENDING_ISSUE, certificateRepository.findByUuid(cert.getUuid()).orElseThrow().getState());

        // Drive poll: attempt 2 → IN_PROGRESS (re-enqueue)
        CertificateStatusPollMessage msg2 = new CertificateStatusPollMessage(Resource.CERTIFICATE, cert.getUuid(), CertificateOperation.ISSUE, 2);
        pollListener.processMessage(msg2);
        assertEquals(CertificateState.PENDING_ISSUE, certificateRepository.findByUuid(cert.getUuid()).orElseThrow().getState());

        // Drive poll: attempt 3 → COMPLETED with cert data → ISSUED
        CertificateStatusPollMessage msg3 = new CertificateStatusPollMessage(Resource.CERTIFICATE, cert.getUuid(), CertificateOperation.ISSUE, 3);
        pollListener.processMessage(msg3);

        Certificate final_ = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.ISSUED, final_.getState(),
                "After COMPLETED poll response, cert must be ISSUED");
        assertNotNull(final_.getCertificateContent(),
                "After async COMPLETED, certificateContent must be set (was null — data-loss bug)");
        assertNotNull(final_.getCertificateContent().getContent(),
                "After async COMPLETED, certificate bytes must be persisted");
        assertTrue(final_.getCertificateContent().getContent().length() > 0,
                "After async COMPLETED, certificate bytes must be non-empty");
        assertNotNull(final_.getSerialNumber(),
                "After async COMPLETED, serial number must be parsed from cert bytes");

        // Verify issue endpoint was called once, status endpoint called 3 times
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_PATH)));
        mockServer.verify(3, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_STATUS_PATH)));
    }
}
