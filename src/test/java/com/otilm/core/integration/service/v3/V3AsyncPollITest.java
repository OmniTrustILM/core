package com.otilm.core.integration.service.v3;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;

import static com.github.tomakehurst.wiremock.client.WireMock.moreThanOrExactly;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.jms.listeners.poll.CertificateStatusPollSweeper;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import com.otilm.core.util.BaseMessagingIntTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;

/**
 * Real-broker integration test for the v3 async-poll cycle.
 *
 * <p>Drives the full stack: {@link ClientOperationExternalService#registerCertificate} → 202 async
 * accept → {@code certificate_status_poll} row → {@link CertificateStatusPollSweeper#sweep()}
 * → poll message to RabbitMQ → {@code CertificateStatusPollListener} → WireMock register-status
 * endpoint → state-machine transition.
 *
 * <p>{@code @ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)} is required:
 * the base {@code "test"} profile disables {@code PollJmsEndpointConfig}
 * ({@code @Profile("!test")}); overriding prevents that profile from being inherited so the poll
 * listener container starts. Mirror of the pattern used by {@code JmsListenerIntegrationTest} and
 * {@code CertificateUploadMessagingIntTest}.
 *
 * <p>{@code provider.status-poll.by-kind.REGISTER.max-attempts=2} is set via
 * {@link TestPropertySource} so the timeout scenario completes in exactly two sweeps instead of
 * the production default of 50.
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
// Poll timing is driven by makePollDueNow() back-dating, not by configured delays.
// max-attempts=2 is load-bearing: limits the timeout test to exactly two sweeps.
// delays[0] initialises the required non-null delays list; the value is irrelevant because
// makePollDueNow() back-dates the row rather than relying on the configured interval.
@TestPropertySource(properties = {
        "provider.status-poll.by-kind.REGISTER.delays[0]=PT0S",
        "provider.status-poll.by-kind.REGISTER.max-attempts=2"
})
class V3AsyncPollITest extends BaseMessagingIntTest {

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private ClientOperationExternalService clientOperationService;

    @Autowired
    private CertificateStatusPollSweeper sweeper;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateStatusPollRepository pollRepository;

    @Autowired
    private CertificateStatusPollWriter pollWriter;

    // Spied for parity with the issue-driving suites; this suite stubs/verifies no interactions on it.
    @MockitoSpyBean
    @SuppressWarnings("unused")
    private ActionProducer actionProducer;

    // Fixture builder repos
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    // ── Per-test state ────────────────────────────────────────────────────────

    private WireMockServer wireMockServer;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @BeforeEach
    public void setUpWireMock() {
        wireMockServer = new WireMockServer(0);
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());
    }

    @AfterEach
    public void tearDownWireMock() {
        wireMockServer.stop();
    }

    // ── Scenario 1: Completion ────────────────────────────────────────────────

    /**
     * Completion scenario: stateful status stub returns IN_PROGRESS on the first poll then
     * COMPLETED on the second.
     *
     * <ol>
     *   <li>Seed a PENDING_REGISTRATION cert with a poll row due now via async register (202).</li>
     *   <li>First {@code sweep()}: listener calls the stub → IN_PROGRESS → poll row survives
     *       (next_poll_at advanced), cert stays PENDING_REGISTRATION.</li>
     *   <li>Second {@code sweep()}: listener calls the stub → COMPLETED → cert transitions to
     *       REGISTERED, poll row is deleted.</li>
     * </ol>
     */
    @Test
    void registerAsync_completionFlow_reachesRegistered() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture(
                FeatureFlag.CERTIFICATE_REGISTRATION,
                FeatureFlag.CERTIFICATE_STATUS_POLLING);

        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        V3ConnectorStubs.stubRegisterAsync(wireMockServer, null);
        V3ConnectorStubs.stubRegisterStatus(wireMockServer, "completion-" + UUID.randomUUID());

        ClientCertificateDataResponseDto response = registerCertificate(fixture, "CN=poll-complete,O=Test");
        UUID certUuid = UUID.fromString(response.getUuid());

        // Pre-condition: cert is PENDING_REGISTRATION and poll row exists
        Certificate certAfterRegister = reloadCert(certUuid);
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, certAfterRegister.getState(),
                "Pre-condition: async register must park cert in PENDING_REGISTRATION");
        long initialPollRows = countPollRows(certUuid);
        Assertions.assertEquals(1L, initialPollRows,
                "Pre-condition: async register with both flags must create exactly one poll row");

        // Advance the poll row's next_poll_at to now so the sweeper picks it up immediately
        makePollDueNow(certUuid);

        // First sweep → IN_PROGRESS → row survives; cert stays PENDING_REGISTRATION.
        // Await until the stub was called once — this confirms the listener processed the first
        // poll message and the scenario state has advanced to COMPLETED in WireMock.
        sweeper.sweep();
        await().atMost(5, TimeUnit.SECONDS)
                .pollInterval(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> {
                    // Confirm the status endpoint was called at least once (listener has run)
                    wireMockServer.verify(moreThanOrExactly(1), postRequestedFor(urlEqualTo(V3ConnectorStubs.REGISTER_STATUS)));
                    // Row must still exist (rescheduled to a future next_poll_at by the claimer)
                    long rowCount = countPollRows(certUuid);
                    Certificate current = reloadCert(certUuid);
                    Assertions.assertEquals(1L, rowCount,
                            "After first sweep (IN_PROGRESS): poll row must still exist");
                    Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, current.getState(),
                            "After first sweep (IN_PROGRESS): cert must remain PENDING_REGISTRATION");
                });

        // Advance again so the rescheduled row is due for the second sweep
        makePollDueNow(certUuid);

        // Second sweep → COMPLETED → cert transitions to REGISTERED, row deleted
        sweeper.sweep();
        await().atMost(5, TimeUnit.SECONDS)
                .pollInterval(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> {
                    Certificate current = reloadCert(certUuid);
                    long rowCount = countPollRows(certUuid);
                    Assertions.assertEquals(CertificateState.REGISTERED, current.getState(),
                            "After second sweep (COMPLETED): cert must reach REGISTERED");
                    Assertions.assertEquals(0L, rowCount,
                            "After second sweep (COMPLETED): poll row must be deleted");
                });
    }

    // ── Scenario 2: Timeout ───────────────────────────────────────────────────

    /**
     * Timeout scenario: status stub always returns IN_PROGRESS. With max-attempts=2 the listener
     * applies a timeout failure on the second poll (attempt 1: {@code 1 + 1 >= 2}).
     *
     * <ol>
     *   <li>Seed a PENDING_REGISTRATION cert with a poll row due now.</li>
     *   <li>First {@code sweep()}: listener → IN_PROGRESS, attempt 0 → not yet timed out → row
     *       survives, cert stays PENDING_REGISTRATION.</li>
     *   <li>Second {@code sweep()}: listener → IN_PROGRESS, attempt 1 → last attempt → cert
     *       transitions to FAILED, row deleted.</li>
     * </ol>
     */
    @Test
    void registerAsync_timeoutFlow_reachesFailed() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture(
                FeatureFlag.CERTIFICATE_REGISTRATION,
                FeatureFlag.CERTIFICATE_STATUS_POLLING);

        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        V3ConnectorStubs.stubRegisterAsync(wireMockServer, null);
        V3ConnectorStubs.stubRegisterStatusAlwaysInProgress(wireMockServer);

        ClientCertificateDataResponseDto response = registerCertificate(fixture, "CN=poll-timeout,O=Test");
        UUID certUuid = UUID.fromString(response.getUuid());

        // Pre-condition: cert is PENDING_REGISTRATION with poll row
        Certificate certAfterRegister = reloadCert(certUuid);
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, certAfterRegister.getState(),
                "Pre-condition: async register must park cert in PENDING_REGISTRATION");
        Assertions.assertEquals(1L, countPollRows(certUuid),
                "Pre-condition: async register with both flags must create exactly one poll row");

        makePollDueNow(certUuid);

        // First sweep → IN_PROGRESS at attempt 0 → not last attempt (0+1 < 2) → row survives.
        // Await until the stub was called once to confirm the listener ran before the second sweep.
        sweeper.sweep();
        await().atMost(5, TimeUnit.SECONDS)
                .pollInterval(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> {
                    // Confirm the status endpoint was called at least once (listener has run)
                    wireMockServer.verify(moreThanOrExactly(1), postRequestedFor(urlEqualTo(V3ConnectorStubs.REGISTER_STATUS)));
                    Certificate current = reloadCert(certUuid);
                    Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, current.getState(),
                            "After first sweep (IN_PROGRESS, not timed out): cert must remain PENDING_REGISTRATION");
                    Assertions.assertEquals(1L, countPollRows(certUuid),
                            "After first sweep (IN_PROGRESS, not timed out): poll row must survive");
                });

        makePollDueNow(certUuid);

        // Second sweep → IN_PROGRESS at attempt 1 → last attempt (1+1 >= 2) → FAILED, row deleted
        sweeper.sweep();
        await().atMost(5, TimeUnit.SECONDS)
                .pollInterval(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> {
                    Certificate current = reloadCert(certUuid);
                    long rowCount = countPollRows(certUuid);
                    Assertions.assertEquals(CertificateState.FAILED, current.getState(),
                            "After second sweep (IN_PROGRESS at max attempts): cert must reach FAILED");
                    Assertions.assertEquals(0L, rowCount,
                            "After second sweep (timeout): poll row must be deleted");
                });
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private AuthorityFixtures.Repos repos() {
        return new AuthorityFixtures.Repos(
                connectorRepository,
                functionGroupRepository,
                connector2FunctionGroupRepository,
                authorityInstanceReferenceRepository,
                raProfileRepository,
                connectorInterfaceRepository);
    }

    private AuthorityFixtures.Fixture buildV3Fixture(FeatureFlag... features) {
        return AuthorityFixtures.v3Authority(repos(), wireMockServer, features);
    }

    private ClientCertificateDataResponseDto registerCertificate(AuthorityFixtures.Fixture fixture, String subjectDn)
            throws Exception {
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn(subjectDn);
        return clientOperationService.registerCertificate(
                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                fixture.raProfile().getSecuredUuid(),
                request);
    }

    private Certificate reloadCert(UUID uuid) {
        return certificateRepository.findByUuid(uuid)
                .orElseThrow(() -> new AssertionError("Certificate not found: " + uuid));
    }

    private long countPollRows(UUID certUuid) {
        return pollRepository.findAll().stream()
                .filter(p -> certUuid.equals(p.getCertificateUuid()))
                .count();
    }

    /**
     * Back-dates the poll row for the given certificate to {@code now()} so the sweeper's
     * due-time query picks it up immediately without waiting for the backoff delay.
     * Preserves the current {@code attempt} value in the row so {@code isLastAttempt} sees
     * the correct attempt count.
     */
    private void makePollDueNow(UUID certUuid) {
        int currentAttempt = pollRepository.findAll().stream()
                .filter(p -> certUuid.equals(p.getCertificateUuid()))
                .map(p -> p.getAttempt())
                .findFirst()
                .orElseThrow(() -> new AssertionError("No poll row for cert " + certUuid + " — already consumed or never created"));
        pollWriter.reschedule(certUuid, currentAttempt, OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(1));
    }
}
