package com.otilm.core.integration.api.est;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.IssueActionData;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import com.zaxxer.hikari.HikariDataSource;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicAuthorization;
import static com.otilm.core.util.EstClientCredentialsFixtures.certificateHeader;
import static com.otilm.core.util.PkiFixtures.CLIENT_SUBJECT;
import static com.otilm.core.util.PkiFixtures.clientCertificate;
import static com.otilm.core.util.PkiFixtures.intermediateCa;
import static com.otilm.core.util.PkiFixtures.raCertificate;
import static com.otilm.core.util.PkiFixtures.rootCa;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/**
 * {@code /simpleenroll} over HTTP through the real filter and interceptor chain, until the certificate is issued: every
 * authentication policy, the route that a label naming an RA Profile resolves to, and the connection pool while the
 * request waits. Nothing here consumes the issue that a request queues, so each test takes it from the mocked broker
 * and issues it as the consumer would, while the request waits for the certificate.
 */
class EstEnrollmentHttpITest extends AbstractEstHttpITest {

    private static final String LABEL = "devices";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "p4ssw0rd";
    private static final Duration QUEUE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration ANSWER_TIMEOUT = Duration.ofSeconds(30);
    private static final int POOL_SAMPLES = 20;
    private static final Duration POOL_SAMPLE_INTERVAL = Duration.ofMillis(50);
    private static final Duration POOL_SAMPLING_TIMEOUT = Duration.ofSeconds(10);

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private JmsTemplate jmsTemplate;

    @Autowired
    private DataSource dataSource;

    @Value("${server.ssl.certificate-header-name}")
    private String certificateHeaderName;

    private Ca issuingCa;
    private Certificate trustedRoot;
    private RaProfile raProfile;
    private Secret credentialSecret;
    private X509Certificate issued;
    private final ExecutorService requestThread = Executors.newSingleThreadExecutor();

    @BeforeEach
    void seedTheMaterialOfEveryPolicyAndAConnectorThatIssuesAtOnce() {
        Ca root = rootCa("EST Root CA");
        issuingCa = intermediateCa(root, "EST Issuing CA");
        trustedRoot = seeder.seedCertificate(root.certificate());
        raProfile = saveRaProfile(RA_PROFILE_NAME);
        credentialSecret = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        registrations.seedRegistration(raProfile, CLIENT_SUBJECT);
        issued = clientCertificate(rootCa("CA of the connector"));
        AuthorityV2ConnectorStubs.on(connectorServer).stubIssue(issued).stubIssueAttributeValidation();
    }

    /** Interrupts a request that still waits, so that it ends before the next test cleans the database. */
    @AfterEach
    void stopTheRequestThread() throws InterruptedException {
        requestThread.shutdownNow();
        if (!requestThread.awaitTermination(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            throw new IllegalStateException("The enrolment request did not stop");
        }
    }

    // ── Issuance ──────────────────────────────────────────────────────────────

    @Nested
    class Issuance {

        @ParameterizedTest
        @EnumSource(EstAuthenticationPolicy.class)
        void answersIssuedCertificate_whenTheQueuedIssueCompletesDuringTheWait(EstAuthenticationPolicy policy)
                throws Exception {
            // given
            seedEstProfileRoute(policy);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

            // when
            Future<MockHttpServletResponse> enrolment = enrollInTheBackground(LABEL, csr, buildCredentials(policy));
            issueAsTheConsumerWould(awaitQueuedIssue());
            MockHttpServletResponse response = enrolment.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(readCertificate(response)).isEqualTo(issued);
        }

        @Test
        void answersIssuedCertificate_whenLabelNamesTheRaProfile() throws Exception {
            // given
            EstProfile activated = seeder
                    .seedEstProfile("est-activated", EstAuthenticationPolicy.RA_BASIC, null, List.of(credentialSecret),
                            List.of());
            seeder.activateEst(raProfile, activated);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

            // when
            Future<MockHttpServletResponse> enrolment = enrollInTheBackground(RA_PROFILE_NAME, csr,
                    buildCredentials(EstAuthenticationPolicy.RA_BASIC));
            issueAsTheConsumerWould(awaitQueuedIssue());
            MockHttpServletResponse response = enrolment.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(readCertificate(response)).isEqualTo(issued);
        }
    }

    // ── ConnectionPool ────────────────────────────────────────────────────────

    @Nested
    class ConnectionPool {

        @Test
        void holdsNoPooledConnection_whenTheRequestWaitsForTheCertificate() throws Exception {
            // given — the queued issue stays open until the test issues it
            seedEstProfileRoute(EstAuthenticationPolicy.RA_BASIC);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);
            int idle = countIdleConnections();

            // when
            Future<MockHttpServletResponse> enrolment = enrollInTheBackground(LABEL, csr,
                    buildCredentials(EstAuthenticationPolicy.RA_BASIC));
            ActionMessage queued = awaitQueuedIssue();
            List<Integer> inUseWhileWaiting = sampleActiveConnections();
            issueAsTheConsumerWould(queued);
            MockHttpServletResponse response = enrolment.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

            // then
            assertThat(inUseWhileWaiting)
                    .as("connections in use while the request waits, against %d when idle", idle)
                    .filteredOn(inUse -> inUse > idle)
                    .hasSizeLessThan(POOL_SAMPLES / 2);
            assertThat(response.getStatus()).isEqualTo(200);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** The fewest connections in use among a few samples, so that a background task does not raise it. */
        private int countIdleConnections() {
            return sampleActiveConnections().stream().mapToInt(Integer::intValue).min().orElseThrow();
        }

        private List<Integer> sampleActiveConnections() {
            List<Integer> samples = new ArrayList<>();
            Awaitility.await().atMost(POOL_SAMPLING_TIMEOUT).pollInterval(POOL_SAMPLE_INTERVAL).until(() -> {
                samples.add(countActiveConnections());
                return samples.size() >= POOL_SAMPLES;
            });
            return samples;
        }

        private int countActiveConnections() throws SQLException {
            return dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean().getActiveConnections();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void seedEstProfileRoute(EstAuthenticationPolicy policy) {
        seeder.seedEstProfile(LABEL, policy, raProfile, List.of(credentialSecret), List.of(trustedRoot));
    }

    /** What a client of the policy presents that the route accepts. */
    private Credentials buildCredentials(EstAuthenticationPolicy policy) {
        return switch (policy) {
            case RA_BASIC -> new Credentials(basicAuthorization(USERNAME, PASSWORD), null);
            case CERTIFICATE_REGISTRATION ->
                new Credentials(basicAuthorization("", CertificateRegistrationSeeder.CHALLENGE), null);
            case VENDOR_MTLS ->
                new Credentials(null, certificateHeader(clientCertificate(issuingCa), issuingCa.certificate()));
            case RA_MTLS -> new Credentials(null, certificateHeader(raCertificate(issuingCa), issuingCa.certificate()));
        };
    }

    private Future<MockHttpServletResponse> enrollInTheBackground(String label, byte[] csr, Credentials credentials) {
        MockHttpServletRequestBuilder enrolment = estPost(label + "/simpleenroll", csr);
        if (credentials.authorization() != null) {
            enrolment.header(HttpHeaders.AUTHORIZATION, credentials.authorization());
        }
        if (credentials.certificate() != null) {
            enrolment.header(certificateHeaderName, credentials.certificate());
        }
        return requestThread.submit(() -> mockMvc.perform(enrolment).andReturn().getResponse());
    }

    /** The issue that the request queued, taken from the broker as its consumer would take it. */
    private ActionMessage awaitQueuedIssue() {
        ArgumentCaptor<ActionMessage> queued = ArgumentCaptor.forClass(ActionMessage.class);
        verify(jmsTemplate, timeout(QUEUE_TIMEOUT.toMillis()))
                .convertAndSend(anyString(), queued.capture(), any(MessagePostProcessor.class));
        return queued.getValue();
    }

    /** Issues for the request that the issue was queued for, as the actions listener does. */
    private void issueAsTheConsumerWould(ActionMessage queued) throws Exception {
        clientOperationService
                .issueCertificateAction(queued.getResourceUuid(),
                        IssueActionData.certificateRequestUuidOf(queued.getData()), false);
    }

    /** The two headers by which a client presents credentials; {@code null} for one that it does not send. */
    private record Credentials(String authorization, String certificate) {
    }
}
