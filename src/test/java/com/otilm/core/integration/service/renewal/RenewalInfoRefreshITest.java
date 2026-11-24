package com.otilm.core.integration.service.renewal;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.api.model.core.raprofile.RaProfileRenewalSettingsUpdateDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository.RefreshClaim;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.service.handler.authority.AuthorityProviderV3Adapter;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.renewal.refresh.AuthorityRefresh;
import com.otilm.core.service.renewal.refresh.RefreshBatch;
import com.otilm.core.service.renewal.refresh.RenewalInfoEnrolment;
import com.otilm.core.service.renewal.refresh.RenewalInfoRefreshClaimer;
import com.otilm.core.service.renewal.refresh.RenewalInfoRefreshRunner;
import com.otilm.core.service.renewal.refresh.RenewalInfoResultApplier;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.builders.AuthorityFixtures;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RenewalInfoRefreshITest extends BaseSpringBootTest {

    private static final String RENEWAL_INFO_PATH = "/v3/authorityProvider/certificates/renewalInfo";
    private static final String WINDOW_START = "2026-12-20T00:00:00Z";
    private static final String WINDOW_END = "2026-12-22T00:00:00Z";
    private static final Duration LEASE = Duration.ofMinutes(15);
    private static final Duration RECHECK = Duration.ofDays(7);
    private static final Duration SLACK = Duration.ofMinutes(1);

    @Autowired
    private RenewalInfoRefreshClaimer claimer;
    @Autowired
    private RenewalInfoRefreshRunner runner;
    @Autowired
    private RenewalRefreshWriter refreshWriter;
    @Autowired
    private RenewalInfoResultApplier applier;
    @Autowired
    private AuthorityProviderV3Adapter adapter;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private RaProfileExternalService raProfileService;
    @Autowired
    private CertificateStateMachine stateMachine;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
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
    @Autowired
    private PlatformTransactionManager transactionManager;

    private final List<WireMockServer> connectors = new ArrayList<>();

    @AfterEach
    void stopConnectors() {
        connectors.forEach(WireMockServer::stop);
    }

    // ── Statuses ──────────────────────────────────────────────────────────────

    @Test
    void appliesEveryStatus_andLogsNoCertificateContent() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate available = seedDueCertificate(raProfile);
        Certificate unknown = seedDueCertificate(raProfile);
        Certificate notSupported = seedDueCertificate(raProfile);
        Certificate retry = seedDueCertificate(raProfile);
        stubAnswer(connector, result(available, "available"), result(unknown, "unknown"),
                result(notSupported, "notSupported"), result(retry, "retry"));
        Instant now = Instant.now();

        // when
        List<String> logged;
        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            refresh(now);
            logged = probe.logged();
        }

        // then
        CertificateRenewalInfo availableRow = rowOf(available);
        assertThat(availableRow.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertThat(availableRow.getWindowStart()).isEqualTo(Instant.parse(WINDOW_START));
        assertThat(availableRow.getRefreshAttempt()).isZero();
        assertThat(availableRow.getNextRefreshAt())
                .isBetween(now.plus(Duration.ofMinutes(100)), now.plus(Duration.ofMinutes(140)));
        for (Certificate noAdvice : List.of(unknown, notSupported)) {
            CertificateRenewalInfo row = rowOf(noAdvice);
            assertThat(row.isRefreshUnsupported()).isTrue();
            assertThat(row.getNextRefreshAt()).isAfter(now.plus(RECHECK).minus(SLACK));
        }
        CertificateRenewalInfo retryRow = rowOf(retry);
        assertThat(retryRow.getRefreshAttempt()).isEqualTo(1);
        assertThat(retryRow.getWindowStart()).isNull();
        connector.verify(1, postRequestedFor(urlEqualTo(RENEWAL_INFO_PATH)));
        assertThat(logged).isNotEmpty().noneMatch(line -> line.contains("MII"));
    }

    @Test
    void backsTheBatchOff_andLogsNoCertificateContent_whenTheConnectorIsUnavailable() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        connector.stubFor(post(urlEqualTo(RENEWAL_INFO_PATH)).willReturn(aResponse().withStatus(503)));
        Instant now = Instant.now();

        // when
        List<String> logged;
        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            refresh(now);
            logged = probe.logged();
        }

        // then
        CertificateRenewalInfo row = rowOf(certificate);
        assertThat(logged).isNotEmpty().noneMatch(line -> line.contains("MII"));
        assertThat(row.getRefreshAttempt()).isEqualTo(1);
        assertThat(row.getNextRefreshAt())
                .isBetween(now.plus(Duration.ofMinutes(5)), now.plus(Duration.ofMinutes(5)).plus(SLACK));
    }

    @Test
    void suspendsTheRefresh_whenTheConnectorDoesNotServeIt() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        connector.stubFor(post(urlEqualTo(RENEWAL_INFO_PATH)).willReturn(aResponse().withStatus(404)));
        Instant now = Instant.now();

        // when
        refresh(now);

        // then
        CertificateRenewalInfo row = rowOf(certificate);
        assertThat(row.getRefreshAttempt()).isZero();
        assertThat(row.getNextRefreshAt()).isAfter(now.plus(RECHECK).minus(SLACK));
    }

    // ── Claiming ──────────────────────────────────────────────────────────────

    @Test
    void doesNotClaimUnsupportedCertificates_beforeTheirRecheck() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        stubAnswer(connector, result(certificate, "unknown"));
        Instant now = Instant.now();
        refresh(now);

        // when
        Set<UUID> beforeRecheck = claimedCertificates(claimer.claim(now.plus(Duration.ofDays(6))));
        Set<UUID> afterRecheck = claimedCertificates(claimer.claim(now.plus(RECHECK).plus(SLACK)));

        // then
        assertThat(beforeRecheck).isEmpty();
        assertThat(afterRecheck).containsExactly(certificate.getUuid());
    }

    @Test
    void claimsALostBatchAgain_afterTheLease() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        Instant now = Instant.now();
        Set<UUID> claimed = claimedCertificates(claimer.claim(now));

        // when
        Set<UUID> duringLease = claimedCertificates(claimer.claim(now.plus(LEASE).minus(SLACK)));
        Set<UUID> afterLease = claimedCertificates(claimer.claim(now.plus(LEASE).plusSeconds(1)));

        // then
        assertThat(claimed).containsExactly(certificate.getUuid());
        assertThat(duringLease).isEmpty();
        assertThat(afterLease).containsExactly(certificate.getUuid());
    }

    @Test
    void skipsARowAnotherTransactionHolds_withoutWaitingForIt() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(connector(), true);
        Certificate heldByAWriter = seedDueCertificate(raProfile);
        Certificate free = seedDueCertificate(raProfile);
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService threads = Executors.newFixedThreadPool(2);
        Instant now = Instant.now();

        try {
            Future<?> holding = threads
                    .submit(() -> new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                        renewalInfoRepository.findAndLockByCertificateUuid(heldByAWriter.getUuid());
                        locked.countDown();
                        awaitQuietly(release);
                    }));
            assertThat(locked.await(30, TimeUnit.SECONDS)).isTrue();

            // when
            Future<List<RefreshClaim>> claiming = threads
                    .submit(() -> refreshWriter.claimDue(now, 10, now.plus(LEASE)));
            List<RefreshClaim> claimed = claiming.get(30, TimeUnit.SECONDS);
            release.countDown();
            holding.get(30, TimeUnit.SECONDS);

            // then
            assertThat(claimed).extracting(RefreshClaim::getCertificateUuid).containsExactly(free.getUuid());
            assertThat(rowOf(heldByAWriter).getNextRefreshAt()).isBefore(now);
        } finally {
            release.countDown();
            threads.shutdownNow();
        }
    }

    @Test
    void claimsAtMostTheCapOfEachAuthority() {
        // given
        int maxPerAuthority = 2;
        RaProfile first = seedRaProfile(connector(), true);
        RaProfile second = seedRaProfile(connector(), true);
        for (int i = 0; i < 3; i++) {
            seedDueCertificate(first);
        }
        Certificate ofSecond = seedDueCertificate(second);
        Instant now = Instant.now();

        // when
        List<RefreshClaim> claimed = refreshWriter.claimDue(now, maxPerAuthority, now.plus(LEASE));

        // then
        assertThat(claimed).hasSize(3);
        assertThat(claimed)
                .filteredOn(claim -> claim.getRaProfileUuid().equals(first.getUuid()))
                .hasSize(maxPerAuthority);
        assertThat(claimed).extracting(RefreshClaim::getCertificateUuid).contains(ofSecond.getUuid());
    }

    @Test
    void enrolsAtMostTheCap_whenMoreCertificatesAreEligible() {
        // given
        int enrolPerSweep = 1;
        RaProfile raProfile = seedRaProfile(connector(), true);
        seedCertificate(raProfile, CertificateState.ISSUED);
        seedCertificate(raProfile, CertificateState.ISSUED);

        // when
        int enrolled = refreshWriter.enrolEligible(Instant.now(), 60, enrolPerSweep);

        // then
        assertThat(enrolled).isEqualTo(enrolPerSweep);
    }

    @Test
    void claimsNoIneligibleCertificate_andEndsTheirRefresh() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate revoked = seedDueCertificate(raProfile);
        Certificate expired = seedDueCertificate(raProfile);
        Certificate archived = seedDueCertificate(raProfile);
        Certificate replaced = seedDueCertificate(raProfile);
        revoked.setState(CertificateState.REVOKED);
        expired.setNotAfter(Date.from(Instant.now().minus(Duration.ofDays(1))));
        archived.setArchived(true);
        certificateRepository.saveAll(List.of(revoked, expired, archived));
        seedRenewal(replaced, seedCertificate(raProfile, CertificateState.ISSUED));

        // when
        List<AuthorityRefresh> refreshes = claimer.claim(Instant.now());

        // then
        assertThat(claimedCertificates(refreshes)).isEmpty();
        for (Certificate certificate : List.of(revoked, expired, archived, replaced)) {
            assertThat(rowOf(certificate).getNextRefreshAt()).isNull();
        }
        connector.verify(0, postRequestedFor(urlEqualTo(RENEWAL_INFO_PATH)));
    }

    // ── Enrolment ─────────────────────────────────────────────────────────────

    @Test
    void enrolsACertificate_whenItIsIssued() {
        // given
        RaProfile raProfile = seedRaProfile(connector(), true);
        Certificate certificate = seedCertificate(raProfile, CertificateState.PENDING_ISSUE);
        Instant before = Instant.now();

        // when
        stateMachine.transition(certificate, CertificateState.ISSUED);

        // then
        assertThat(rowOf(certificate).getNextRefreshAt())
                .isBetween(before, Instant.now().plusSeconds(RenewalInfoEnrolment.ENROL_DELAY_SECONDS));
    }

    @Test
    void endsTheRefresh_whenTheCertificateIsRevoked() {
        // given
        RaProfile raProfile = seedRaProfile(connector(), true);
        Certificate certificate = seedDueCertificate(raProfile);

        // when
        stateMachine.transition(certificate, CertificateState.REVOKED);

        // then
        assertThat(rowOf(certificate).getNextRefreshAt()).isNull();
    }

    @Test
    void endsTheRefreshOfThePredecessor_whenItsSuccessorIsIssued() {
        // given
        RaProfile raProfile = seedRaProfile(connector(), true);
        Certificate predecessor = seedDueCertificate(raProfile);
        Certificate successor = seedCertificate(raProfile, CertificateState.PENDING_ISSUE);
        seedRenewal(predecessor, successor);

        // when
        stateMachine.transition(successor, CertificateState.ISSUED);

        // then
        assertThat(rowOf(predecessor).getNextRefreshAt()).isNull();
        assertThat(rowOf(successor).getNextRefreshAt()).isNotNull();
    }

    @Test
    void enrolsNothing_whenTheConnectorDoesNotAdvertiseRenewalInformation() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = raProfileOn(AuthorityFixtures
                .v3Authority(repos(), connector, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)
                .raProfile(), true);
        Certificate certificate = seedCertificate(raProfile, CertificateState.PENDING_ISSUE);

        // when
        stateMachine.transition(certificate, CertificateState.ISSUED);

        // then
        assertThat(renewalInfoRepository
                .findByCertificateUuid(certificate.getUuid())
                .map(CertificateRenewalInfo::getNextRefreshAt)).isEmpty();
    }

    @Test
    void startsTheRefresh_whenTheRaProfileTurnsTheAuthorityInformationOn() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(connector(), false);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Instant before = Instant.now();

        // when
        updateUseAuthorityRenewalInfo(raProfile, true);

        // then
        assertThat(rowOf(certificate).getNextRefreshAt()).isBetween(before, Instant.now().plus(Duration.ofHours(6)));
    }

    @Test
    void stopsCalling_whenTheRaProfileTurnsTheAuthorityInformationOff() throws Exception {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        stubAnswer(connector, result(certificate, "available"));

        // when
        updateUseAuthorityRenewalInfo(raProfile, false);
        refresh(Instant.now().plus(Duration.ofDays(2)));

        // then
        assertThat(rowOf(certificate).getNextRefreshAt()).isNull();
        connector.verify(0, postRequestedFor(urlEqualTo(RENEWAL_INFO_PATH)));
    }

    @Test
    void dropsTheAuthorityWindow_whenTheRaProfileTurnsTheAuthorityInformationOff() throws Exception {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        stubAnswer(connector, result(certificate, "available"));
        refresh(Instant.now());
        RenewalWindowSource sourceBefore = rowOf(certificate).getSource();

        // when
        updateUseAuthorityRenewalInfo(raProfile, false);

        // then
        CertificateRenewalInfo row = rowOf(certificate);
        assertThat(sourceBefore).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertThat(row.getSource()).isNull();
        assertThat(row.getWindowStart()).isNull();
    }

    // ── Isolation and high availability ───────────────────────────────────────

    @Test
    void refreshesOneAuthority_whileAnotherDoesNotAnswer() {
        // given
        WireMockServer hanging = connector();
        WireMockServer answering = connector();
        Certificate ofHanging = seedDueCertificate(seedRaProfile(hanging, true));
        Certificate ofAnswering = seedDueCertificate(seedRaProfile(answering, true));
        hanging
                .stubFor(post(urlEqualTo(RENEWAL_INFO_PATH))
                        .willReturn(okJson(answer(result(ofHanging, "available"))).withFixedDelay(2_500)));
        stubAnswer(answering, result(ofAnswering, "available"));
        RenewalInfoRefreshRunner pool = runner(adapter, 4, 10);

        // when
        try {
            claimer.claim(Instant.now()).forEach(pool::submit);

            // then
            assertThat(eventually(() -> rowOf(ofAnswering).getSource() == RenewalWindowSource.AUTHORITY)).isTrue();
            assertThat(rowOf(ofHanging).getSource()).isNull();
        } finally {
            pool.shutdown();
        }
    }

    @Test
    void twoClaimersRunningTogether_neverClaimTheSameCertificate() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(connector(), true);
        List<UUID> due = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            due.add(seedDueCertificate(raProfile).getUuid());
        }
        ExecutorService nodes = Executors.newFixedThreadPool(2);

        try {
            for (int round = 0; round < 5; round++) {
                Instant now = Instant.now();
                refreshWriter.postpone(due, now.minusSeconds(1));
                CyclicBarrier start = new CyclicBarrier(2);

                // when
                Future<List<AuthorityRefresh>> first = nodes.submit(() -> claimTogether(start, now));
                Future<List<AuthorityRefresh>> second = nodes.submit(() -> claimTogether(start, now));
                List<UUID> firstClaimed = certificatesOf(first.get(30, TimeUnit.SECONDS));
                List<UUID> secondClaimed = certificatesOf(second.get(30, TimeUnit.SECONDS));

                // then
                List<UUID> all = new ArrayList<>(firstClaimed);
                all.addAll(secondClaimed);
                assertThat(all).doesNotHaveDuplicates().containsExactlyInAnyOrderElementsOf(due);
            }
        } finally {
            nodes.shutdownNow();
        }
    }

    @Test
    void claimsTheBatchOfANodeThatDiedMidCall_againAfterTheLease() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        Certificate certificate = seedDueCertificate(raProfile);
        stubAnswer(connector, result(certificate, "available"));
        AuthorityProviderV3Adapter dying = mock(AuthorityProviderV3Adapter.class);
        when(dying.renewalInfo(any(), any(), any())).thenThrow(new IllegalStateException("node stopped"));
        RenewalInfoRefreshRunner dyingNode = runner(dying, 1, 1);
        Instant now = Instant.now();
        try {
            claimer.claim(now).forEach(dyingNode::run);
        } finally {
            dyingNode.shutdown();
        }
        Instant leased = rowOf(certificate).getNextRefreshAt();

        // when
        List<AuthorityRefresh> reclaimed = claimer.claim(now.plus(LEASE).plusSeconds(1));
        reclaimed.forEach(runner::run);

        // then
        assertThat(leased).isEqualTo(now.plus(LEASE).truncatedTo(ChronoUnit.MICROS));
        assertThat(claimedCertificates(reclaimed)).containsExactly(certificate.getUuid());
        assertThat(rowOf(certificate).getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
    }

    @Test
    void leavesWorkThePoolCannotTake_toTheLease() {
        // given
        WireMockServer connector = connector();
        RaProfile raProfile = seedRaProfile(connector, true);
        List<Certificate> certificates = List
                .of(seedDueCertificate(raProfile), seedDueCertificate(raProfile), seedDueCertificate(raProfile));
        Instant now = Instant.now();
        claimer.claim(now);
        CountDownLatch release = new CountDownLatch(1);
        AuthorityProviderV3Adapter blocked = mock(AuthorityProviderV3Adapter.class);
        when(blocked.renewalInfo(any(), any(), any())).thenAnswer(invocation -> {
            release.await(30, TimeUnit.SECONDS);
            throw new IllegalStateException("released");
        });
        RenewalInfoRefreshRunner pool = runner(blocked, 1, 1);

        // when
        List<Boolean> accepted = new ArrayList<>();
        try {
            for (Certificate certificate : certificates) {
                accepted
                        .add(pool
                                .submit(new AuthorityRefresh(raProfile.getAuthorityInstanceReferenceUuid(), List
                                        .of(new RefreshBatch(raProfile.getUuid(), List.of(certificate.getUuid()))))));
            }
        } finally {
            release.countDown();
            pool.shutdown();
        }

        // then
        assertThat(accepted).containsExactly(true, true, false);
        Certificate rejected = certificates.get(2);
        assertThat(rowOf(rejected).getNextRefreshAt()).isEqualTo(now.plus(LEASE).truncatedTo(ChronoUnit.MICROS));
        assertThat(claimedCertificates(claimer.claim(now.plus(LEASE).plusSeconds(1)))).contains(rejected.getUuid());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<AuthorityRefresh> claimTogether(CyclicBarrier start, Instant now) throws Exception {
        start.await(30, TimeUnit.SECONDS);
        return claimer.claim(now);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void refresh(Instant now) {
        claimer.claim(now).forEach(runner::run);
    }

    private RenewalInfoRefreshRunner runner(AuthorityProviderV3Adapter callAdapter, int threads, int queueCapacity) {
        return new RenewalInfoRefreshRunner(claimer, certificateRepository, attributeEngine, callAdapter, applier,
                threads, queueCapacity);
    }

    private static boolean eventually(BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(50));
        }
        return condition.getAsBoolean();
    }

    private static Set<UUID> claimedCertificates(List<AuthorityRefresh> refreshes) {
        return new HashSet<>(certificatesOf(refreshes));
    }

    private static List<UUID> certificatesOf(List<AuthorityRefresh> refreshes) {
        return refreshes
                .stream()
                .flatMap(refresh -> refresh.batches().stream())
                .flatMap(batch -> batch.certificateUuids().stream())
                .toList();
    }

    private WireMockServer connector() {
        WireMockServer connector = LoopbackWireMock.start();
        connectors.add(connector);
        return connector;
    }

    private AuthorityFixtures.Repos repos() {
        return new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                connectorInterfaceRepository);
    }

    private RaProfile seedRaProfile(WireMockServer connector, boolean useAuthorityInfo) {
        return raProfileOn(
                AuthorityFixtures.v3Authority(repos(), connector, FeatureFlag.CERTIFICATE_RENEWAL_INFO).raProfile(),
                useAuthorityInfo);
    }

    private RaProfile raProfileOn(RaProfile raProfile, boolean useAuthorityInfo) {
        raProfile.setRenewalUseAuthorityInfo(useAuthorityInfo);
        return raProfileRepository.save(raProfile);
    }

    private Certificate seedDueCertificate(RaProfile raProfile) {
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        refreshWriter.reEnrol(certificate.getUuid(), Instant.now().minusSeconds(1), 0);
        assertThat(rowOf(certificate).getNextRefreshAt()).isNotNull();
        return certificate;
    }

    private Certificate seedCertificate(RaProfile raProfile, CertificateState state) {
        CertificateContent content = new CertificateContent();
        byte[] der = new byte[48];
        der[0] = 0x30;
        der[1] = (byte) 0x82;
        content.setContent(Base64.getEncoder().encodeToString(der) + UUID.randomUUID());
        content = certificateContentRepository.save(content);
        Instant notBefore = Instant.now().truncatedTo(ChronoUnit.SECONDS).minus(Duration.ofDays(50));
        X509CertificateEntity certificate = aCertificate()
                .withSubjectDn("CN=renewal-info")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .withState(state)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withNotBefore(Date.from(notBefore))
                .withNotAfter(Date.from(notBefore.plus(Duration.ofDays(100))))
                .withRaProfile(raProfile)
                .build();
        return certificateRepository.save(certificate);
    }

    private void seedRenewal(Certificate predecessor, Certificate successor) {
        CertificateRelation relation = new CertificateRelation();
        relation.getId().setPredecessorCertificateUuid(predecessor.getUuid());
        relation.getId().setSuccessorCertificateUuid(successor.getUuid());
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(CertificateRelationType.RENEWAL);
        certificateRelationRepository.save(relation);
    }

    private void updateUseAuthorityRenewalInfo(RaProfile raProfile, boolean useAuthorityInfo) throws Exception {
        RaProfileRenewalSettingsUpdateDto request = new RaProfileRenewalSettingsUpdateDto();
        request.setWindowEnabled(false);
        request.setWindowStartPercent(67);
        request.setWindowEndPercent(80);
        request.setUseAuthorityRenewalInfo(useAuthorityInfo);
        raProfileService
                .updateRaProfileRenewalSettings(
                        SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                        SecuredUUID.fromUUID(raProfile.getUuid()), request);
    }

    private CertificateRenewalInfo rowOf(Certificate certificate) {
        return renewalInfoRepository.findByCertificateUuid(certificate.getUuid()).orElseThrow();
    }

    private static void stubAnswer(WireMockServer connector, String... results) {
        connector.stubFor(post(urlEqualTo(RENEWAL_INFO_PATH)).willReturn(okJson(answer(results))));
    }

    private static String answer(String... results) {
        return "{\"retryAfter\": 7200, \"results\": [" + String.join(",", results) + "]}";
    }

    private static String result(Certificate certificate, String status) {
        String window = "available".equals(status)
                ? ", \"windowStart\": \"%s\", \"windowEnd\": \"%s\"".formatted(WINDOW_START, WINDOW_END)
                : "";
        return "{\"reference\": \"%s\", \"status\": \"%s\"%s}".formatted(certificate.getUuid(), status, window);
    }
}
