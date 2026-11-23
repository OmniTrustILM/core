package com.otilm.core.integration.api.est;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.mock.web.MockHttpServletResponse;

import static com.otilm.core.util.EstClientCredentialsFixtures.certificateHeader;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/**
 * {@code /simplereenroll} over HTTP through the real filter and interceptor chain: the client presents only the
 * certificate that it renews, in the header that the proxy forwards it in. Nothing here consumes the renewal that a
 * request queues, so the test that waits for it takes it from the mocked broker and hands it to the actions listener,
 * as the consumer would, while the request waits for the certificate.
 */
class EstReenrollmentHttpITest extends AbstractEstHttpITest {

    private static final String LABEL = "devices";
    private static final String SUBJECT = "CN=device-1,O=Acme";
    private static final String DNS_NAME = "device-1.example";
    private static final Duration VALIDITY = Duration.ofDays(365);
    private static final Duration QUEUE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration ANSWER_TIMEOUT = Duration.ofSeconds(30);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private ActionsListener actionsListener;

    @Autowired
    private JmsTemplate jmsTemplate;

    @Value("${server.ssl.certificate-header-name}")
    private String certificateHeaderName;

    private final ExecutorService requestThread = Executors.newSingleThreadExecutor();
    private Ca issuer;
    private KeyPair deviceKeys;
    private RaProfile raProfile;
    private EstProfile estProfile;

    @BeforeEach
    void seedRouteAndIssuer() {
        issuer = PkiFixtures.rootCa("EST Issuing CA");
        deviceKeys = PkiFixtures.keyPair();
        raProfile = saveRaProfile("devices-ra");
        estProfile = seeder.seedEstProfile(LABEL, true, raProfile);
        AuthorityV2ConnectorStubs.on(connectorServer).stubIssueAttributeValidation();
    }

    /** Interrupts a request that still waits, so that it ends before the next test cleans the database. */
    @AfterEach
    void stopTheRequestThread() throws InterruptedException {
        requestThread.shutdownNow();
        if (!requestThread.awaitTermination(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            throw new IllegalStateException("The re-enrolment request did not stop");
        }
    }

    @Test
    void answersRenewedCertificate_whenClientPresentsItsCertificate() throws Exception {
        // given
        X509Certificate source = issueDueCertificate();
        seeder.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate();
        AuthorityV2ConnectorStubs.on(connectorServer).stubRenew(renewed);
        byte[] request = EstCsrFixtures.signedRequestBody(deviceKeys, SUBJECT, DNS_NAME);

        // when
        Future<MockHttpServletResponse> reenrolment = requestThread
                .submit(() -> mockMvc
                        .perform(estPost(LABEL + "/simplereenroll", request)
                                .header(certificateHeaderName, certificateHeader(source)))
                        .andReturn()
                        .getResponse());
        actionsListener.processMessage(awaitQueuedAction());
        MockHttpServletResponse response = reenrolment.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

        // then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(readCertificate(response)).isEqualTo(renewed);
    }

    @Test
    void refusesReenrollment_whenNoClientCertificateIsPresented() throws Exception {
        // given
        byte[] request = EstCsrFixtures.signedRequestBody(deviceKeys, SUBJECT, DNS_NAME);

        // when
        MockHttpServletResponse response = postToEst(LABEL + "/simplereenroll", request);

        // then
        assertPlainTextError(response, EstError.CERTIFICATE_REJECTED);
    }

    @Test
    void refusesReenrollment_whenSourceIsRevoked() throws Exception {
        // given
        X509Certificate source = issueDueCertificate();
        Certificate seededSource = seeder.seedIssuedCertificate(source, raProfile, estProfile);
        seededSource.setState(CertificateState.REVOKED);
        certificateRepository.save(seededSource);
        byte[] request = EstCsrFixtures.signedRequestBody(deviceKeys, SUBJECT, DNS_NAME);

        // when
        MockHttpServletResponse response = mockMvc
                .perform(estPost(LABEL + "/simplereenroll", request)
                        .header(certificateHeaderName, certificateHeader(source)))
                .andReturn()
                .getResponse();

        // then
        assertPlainTextError(response, EstError.CERTIFICATE_REJECTED);
        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** A certificate of the device past half of its validity, so that it is due when the profile sets no threshold. */
    private X509Certificate issueDueCertificate() {
        Instant notBefore = Instant.now().minus(Duration.ofDays(300));
        return PkiFixtures
                .clientCertificateFor(issuer, deviceKeys, notBefore, notBefore.plus(VALIDITY), SUBJECT,
                        new GeneralName(GeneralName.dNSName, DNS_NAME));
    }

    /** A certificate of the device that was issued a minute ago, as the connector renews one. */
    private X509Certificate issueFreshCertificate() {
        Instant notBefore = Instant.now().minus(Duration.ofMinutes(1));
        return PkiFixtures
                .clientCertificateFor(issuer, deviceKeys, notBefore, notBefore.plus(VALIDITY), SUBJECT,
                        new GeneralName(GeneralName.dNSName, DNS_NAME));
    }

    /** The action that the request queued, taken from the broker as its consumer would take it. */
    private ActionMessage awaitQueuedAction() {
        ArgumentCaptor<ActionMessage> queued = ArgumentCaptor.forClass(ActionMessage.class);
        verify(jmsTemplate, timeout(QUEUE_TIMEOUT.toMillis()))
                .convertAndSend(anyString(), queued.capture(), any(MessagePostProcessor.class));
        return queued.getValue();
    }
}
