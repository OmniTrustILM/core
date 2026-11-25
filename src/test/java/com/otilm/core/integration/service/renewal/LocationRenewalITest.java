package com.otilm.core.integration.service.renewal;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.LocationException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateLocationId;
import com.otilm.core.dao.entity.CertificateRenewalLocation;
import com.otilm.core.dao.entity.Certificate_;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.LocationExternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.renewal.RenewalEligibility;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.service.renewal.auto.AutoRenewalAction;
import com.otilm.core.service.renewal.auto.AutoRenewalAfterCommit;
import com.otilm.core.service.renewal.auto.LocationRenewalHandler;
import com.otilm.core.service.renewal.auto.TriggerContext;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.seeders.AutoRenewalSeeder;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import jakarta.persistence.EntityManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LocationRenewalITest extends BaseSpringBootTest {

    private static final String PUSH_ONLY_ENTRY = "push-only locations";
    private static final String LOCATION_PUSH_PATH = "/v1/entityProvider/entities/[^/]+/locations/push";
    private static final String AUTHORITY_RENEW_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/renew";

    @Autowired
    private AutoRenewalSeeder seeder;
    @Autowired
    private CertificateTypeHandlerRegistry typeHandlerRegistry;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRenewalLocationRepository renewalLocationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateLocationRepository certificateLocationRepository;
    @Autowired
    private CertificateEventHistoryInternalService eventHistoryService;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private AutoRenewalAction autoRenewalAction;
    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private ClientOperationInternalService clientOperationService;
    @Autowired
    private QueuedMessageDelivery delivery;
    @Autowired
    private TriggerInternalService triggerService;
    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;
    @Autowired
    private DataSource dataSource;

    private final LocationExternalService locationStub = mock(LocationExternalService.class);
    private final TriggerContext trigger = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), null, null);
    private Certificate certificate;
    private AutoRenewalAction action;
    private WireMockServer entityProvider;
    private WireMockServer laterIssuingAuthority;
    private WireMockServer authService;
    private WireMockServer authority;

    @BeforeEach
    void seedDueCertificate() {
        certificate = seeder.seedDueCertificate(seeder.seedRaProfile(true));
        LocationRenewalHandler handler = new LocationRenewalHandler(locationStub, renewalLocationRepository,
                renewalInfoRepository, certificateRepository, certificateLocationRepository, eventHistoryService,
                entityManager, transactionManager);
        action = new AutoRenewalAction(renewalInfoRepository, certificateRepository, eventHistoryService, entityManager,
                transactionManager, typeHandlerRegistry, List.of(handler));
    }

    @AfterEach
    void stopServers() {
        for (WireMockServer server : new WireMockServer[]{entityProvider, laterIssuingAuthority, authService}) {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    void storesOneSuccessorPerLocation_whenTwoKeyGeneratingLocationsHoldTheCertificate() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Location mail = seeder.seedKeyGeneratingLocation(certificate, "mail");
        Certificate webSuccessor = stubRenewal(web, CertificateState.PENDING_ISSUE);
        Certificate mailSuccessor = stubRenewal(mail, CertificateState.PENDING_ISSUE);

        // when
        action.perform(certificate, trigger);

        // then
        assertStarted(seeder.locationRow(certificate, web), webSuccessor);
        assertStarted(seeder.locationRow(certificate, mail), mailSuccessor);
        verifyRenewals(web, 1);
        verifyRenewals(mail, 1);
    }

    @Test
    void callsTheLocationRenewalWithoutATransactionOnceTheEventCommitted_whenTheEventRunsInATransaction()
            throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate successor = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.PENDING_ISSUE);
        AtomicReference<UUID> firingUuid = new AtomicReference<>();
        Map<String, Boolean> duringRenewal = new LinkedHashMap<>();
        HikariPoolMXBean pool = dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean();
        int activeBefore = pool.getActiveConnections();
        AtomicInteger activeDuringRenewal = new AtomicInteger(-1);
        when(locationStub
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(web),
                        eq(certificate.getUuid()), any()))
                .thenAnswer(invocation -> {
                    duringRenewal
                            .put("transactionActive", TransactionSynchronizationManager.isActualTransactionActive());
                    duringRenewal.put("eventCommitted", isCommitted(firingUuid.get()));
                    activeDuringRenewal.set(pool.getActiveConnections());
                    requestRenewal(successor, invocation.getArgument(3));
                    return successor.getUuid();
                });

        // when
        fireInEvent(firingUuid);

        // then
        assertThat(duringRenewal)
                .containsExactly(Map.entry("transactionActive", false), Map.entry("eventCommitted", true));
        assertThat(activeDuringRenewal).hasValue(activeBefore);
        assertStarted(seeder.locationRow(certificate, web), successor);
    }

    @Test
    void countsAnAttemptForTheFailedLocationOnly_whenOneLocationFails() throws Exception {
        // given
        Location failing = seeder.seedKeyGeneratingLocation(certificate, "failing");
        Location working = seeder.seedKeyGeneratingLocation(certificate, "working");
        stubFailure(failing);
        Certificate workingSuccessor = stubRenewal(working, CertificateState.PENDING_ISSUE);
        Instant before = Instant.now();

        // when
        ThrowingCallable fire = () -> action.perform(certificate, trigger);

        // then
        assertThatThrownBy(fire).isInstanceOf(RuleException.class).hasMessageContaining("location failing");
        CertificateRenewalLocation failed = seeder.locationRow(certificate, failing);
        assertThat(failed.getAttempt()).isEqualTo(1);
        assertThat(failed.getNotBefore()).isAfterOrEqualTo(before.plus(Duration.ofHours(1)));
        assertThat(failed.getStartedAt()).isNull();
        assertStarted(seeder.locationRow(certificate, working), workingSuccessor);
    }

    @Test
    void retriesOnlyTheFailedLocation_whenItsBackoffIsOverAndTheOtherSucceeded() throws Exception {
        // given
        Location failing = seeder.seedKeyGeneratingLocation(certificate, "failing");
        Location working = seeder.seedKeyGeneratingLocation(certificate, "working");
        stubFailure(failing);
        Certificate workingSuccessor = stubRenewal(working, CertificateState.PENDING_ISSUE);
        assertThatThrownBy(() -> action.perform(certificate, trigger)).isInstanceOf(RuleException.class);
        issue(workingSuccessor);
        endBackoff(seeder.locationRow(certificate, failing));
        Certificate retriedSuccessor = stubRenewal(failing, CertificateState.PENDING_ISSUE);

        // when
        action.perform(certificate, trigger);

        // then
        verifyRenewals(failing, 2);
        verifyRenewals(working, 1);
        assertStarted(seeder.locationRow(certificate, failing), retriedSuccessor);
        assertThat(seeder.locationRow(certificate, working).getCompletedAt()).isNotNull();
    }

    @Test
    void skipsTheRetry_whenTheBackoffOfTheFailedLocationIsNotOver() throws Exception {
        // given
        Location failing = seeder.seedKeyGeneratingLocation(certificate, "failing");
        stubFailure(failing);
        assertThatThrownBy(() -> action.perform(certificate, trigger)).isInstanceOf(RuleException.class);

        // when
        action.perform(certificate, trigger);

        // then
        verifyRenewals(failing, 1);
        assertThat(seeder.locationRow(certificate, failing).getAttempt()).isEqualTo(1);
    }

    @Test
    void startsNoSecondRenewal_whenTheSuccessorWaitsInApproval() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate inApproval = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.PENDING_APPROVAL);
        seeder.seedLocationRenewal(certificate, web, inApproval);

        // when
        action.perform(certificate, trigger);

        // then
        verifyRenewals(web, 0);
        CertificateRenewalLocation row = seeder.locationRow(certificate, web);
        assertThat(row.getSuccessorUuid()).isEqualTo(inApproval.getUuid());
        assertThat(row.getAttempt()).isZero();
    }

    @Test
    void countsARejectedSuccessorOnce_whenTheNextFiringsFindIt() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate rejected = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REJECTED);
        seeder.seedLocationRenewal(certificate, web, rejected);
        ThrowingCallable firstFiring = () -> action.perform(certificate, trigger);
        assertThatThrownBy(firstFiring).isInstanceOf(RuleException.class).hasMessageContaining("rejected");

        // when
        action.perform(certificate, trigger);

        // then
        CertificateRenewalLocation row = seeder.locationRow(certificate, web);
        assertThat(row.getAttempt()).isEqualTo(1);
        assertThat(row.getSuccessorUuid()).isNull();
        verifyRenewals(web, 0);
    }

    @Test
    void recordsAFailure_whenTheTriggerOwnerMayNotUpdateTheLocation() {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        denyResourceAccess(Resource.LOCATION, ResourceAction.UPDATE);

        // when
        ThrowingCallable fire = () -> autoRenewalAction.perform(certificate, trigger);

        // then
        assertThatThrownBy(fire)
                .isInstanceOf(RuleException.class)
                .hasMessageContaining("location web: the trigger owner may not update the location");
        CertificateRenewalLocation row = seeder.locationRow(certificate, web);
        assertThat(row.getAttempt()).isEqualTo(1);
        assertThat(row.getSuccessorUuid()).isNull();
    }

    @Test
    void namesThePushOnlyLocationsOnce_whenTheCertificateIsHandledRepeatedly() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        seeder.seedPushOnlyLocation(certificate, "balancer");
        seeder.seedPushOnlyLocation(certificate, "appliance");
        stubRenewal(web, CertificateState.PENDING_ISSUE);
        action.perform(certificate, trigger);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .filteredOn(message -> message.contains(PUSH_ONLY_ENTRY))
                .containsExactly("Automatic renewal does not update the push-only locations: appliance, balancer");
        assertThat(renewalLocationRepository.findByCertificateUuid(certificate.getUuid())).hasSize(1);
    }

    @Test
    void keepsTrackingTheSuccessor_whenTheLocationFailedAfterTheRenewalWasRequested() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate requested = stubFailureAfterRequest(web);
        ThrowingCallable firstFiring = () -> action.perform(certificate, trigger);
        assertThatThrownBy(firstFiring).isInstanceOf(RuleException.class).hasMessageContaining("was requested, but");

        // when
        action.perform(certificate, trigger);

        // then
        verifyRenewals(web, 1);
        CertificateRenewalLocation row = seeder.locationRow(certificate, web);
        assertThat(row.getSuccessorUuid()).isEqualTo(requested.getUuid());
        assertThat(row.getAttempt()).isZero();
        assertThat(row.getStartedAt()).isNull();

        // when the successor is issued and the location is fired again
        issue(requested);
        action.perform(certificate, trigger);

        // then the location completes and is not renewed again
        verifyRenewals(web, 1);
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
    }

    @Test
    void completesTheLocationAndNamesIt_whenTheIssuedSuccessorIsNotInTheLocation() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate issuedElsewhere = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.ISSUED);
        seeder.seedLocationRenewal(certificate, web, issuedElsewhere);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .contains("The renewed certificate %s was issued but is not in location web"
                        .formatted(issuedElsewhere.getUuid()));
        verifyRenewals(web, 0);
    }

    @Test
    void completesTheLocationQuietly_whenTheIssuedSuccessorIsInTheLocation() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate issued = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.ISSUED);
        seeder.seedLocationRenewal(certificate, web, issued);
        seeder.seedLocationEntry(web, issued);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .noneMatch(message -> message.contains("is not in location"));
    }

    @Test
    void clearsTheFailureCountersOfOpenLocationsOnly_whenTheWindowChanges() throws Exception {
        // given
        Location failing = seeder.seedKeyGeneratingLocation(certificate, "failing");
        Location completed = seeder.seedKeyGeneratingLocation(certificate, "completed");
        Certificate rejected = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REJECTED);
        CertificateRenewalLocation failedRow = seeder.seedLocationRenewal(certificate, failing, rejected);
        failedRow.setSuccessorUuid(null);
        failedRow.setAttempt(2);
        failedRow.setNotBefore(Instant.now().plus(Duration.ofHours(6)));
        Certificate issued = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.ISSUED);
        CertificateRenewalLocation completedRow = seeder.seedLocationRenewal(certificate, completed, issued);
        completedRow.setAttempt(1);
        completedRow.setCompletedAt(Instant.now());
        renewalLocationRepository.saveAll(List.of(failedRow, completedRow));
        Instant start = Instant.now().plus(Duration.ofDays(2));

        // when
        renewalWindowWriter
                .write(certificate.getUuid(),
                        new WindowWrite.Forced(new Window(start, start.plus(Duration.ofDays(5))), null));

        // then
        CertificateRenewalLocation reset = seeder.locationRow(certificate, failing);
        assertThat(reset.getAttempt()).isZero();
        assertThat(reset.getNotBefore()).isNull();
        assertThat(seeder.locationRow(certificate, completed).getAttempt()).isEqualTo(1);
    }

    @Test
    void completesBothLocations_whenTheRenewalsReplacedTheCertificateInThem() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Location mail = seeder.seedKeyGeneratingLocation(certificate, "mail");
        Certificate webSuccessor = stubReplacingRenewal(web, CertificateState.PENDING_ISSUE);
        Certificate mailSuccessor = stubReplacingRenewal(mail, CertificateState.PENDING_ISSUE);
        action.perform(certificate, trigger);
        issue(webSuccessor);
        issue(mailSuccessor);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
        assertThat(seeder.locationRow(certificate, mail).getCompletedAt()).isNotNull();
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewBlockedReason()).isNull();
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .noneMatch(message -> message.contains("not possible"));
        assertThat(dueForRenewalEvent()).isEmpty();
        verifyRenewals(web, 1);
        verifyRenewals(mail, 1);
    }

    @Test
    void keepsTheRowOpen_whenTheSuccessorIsStillInFlightAfterTheCertificateWasReplaced() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Location mail = seeder.seedKeyGeneratingLocation(certificate, "mail");
        Certificate webSuccessor = stubReplacingRenewal(web, CertificateState.PENDING_ISSUE);
        Certificate mailSuccessor = stubReplacingRenewal(mail, CertificateState.PENDING_APPROVAL);
        action.perform(certificate, trigger);
        issue(webSuccessor);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
        assertStarted(seeder.locationRow(certificate, mail), mailSuccessor);
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewBlockedReason()).isNull();
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .noneMatch(message -> message.contains("not possible"));
        assertThat(dueForRenewalEvent()).containsExactly(certificate.getUuid());
    }

    @Test
    void dropsTheRow_whenTheLocationNoLongerHoldsTheCertificateAndNoSuccessorIsInFlight() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate rejected = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REJECTED);
        seeder.seedLocationRenewal(certificate, web, rejected);
        certificateLocationRepository.deleteById(new CertificateLocationId(web.getUuid(), certificate.getUuid()));

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(renewalLocationRepository.findByCertificateUuid(certificate.getUuid())).isEmpty();
        verifyRenewals(web, 0);
    }

    @Test
    void countsAFailedAttempt_whenTheSuccessorIsRevokedBeforeTheLocationCompleted() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate revoked = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REVOKED);
        seeder.seedRenewalRelation(certificate, revoked);
        seeder.seedLocationRenewal(certificate, web, revoked);
        Instant before = Instant.now();

        // when
        ThrowingCallable fire = () -> action.perform(certificate, trigger);

        // then
        assertThatThrownBy(fire).isInstanceOf(RuleException.class).hasMessageContaining("revoked");
        CertificateRenewalLocation row = seeder.locationRow(certificate, web);
        assertThat(row.getAttempt()).isEqualTo(1);
        assertThat(row.getNotBefore()).isAfterOrEqualTo(before.plus(Duration.ofHours(1)));
        assertThat(row.getSuccessorUuid()).isNull();
        assertThat(row.getCompletedAt()).isNull();
        verifyRenewals(web, 0);
    }

    @Test
    void renewsInTheLocationAgain_whenOnlyARevokedSuccessorIsRelatedAndTheBackoffIsOver() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate revoked = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REVOKED);
        seeder.seedRenewalRelation(certificate, revoked);
        CertificateRenewalLocation row = seeder.seedLocationRenewal(certificate, web, revoked);
        row.setSuccessorUuid(null);
        row.setAttempt(1);
        endBackoff(row);
        Certificate retried = stubRenewal(web, CertificateState.PENDING_ISSUE);

        // when
        action.perform(certificate, trigger);

        // then
        verifyRenewals(web, 1);
        assertStarted(seeder.locationRow(certificate, web), retried);
    }

    @Test
    void reopensTheLocation_whenTheSuccessorIsRevokedAfterTheLocationCompleted() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate revoked = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REVOKED);
        seeder.seedRenewalRelation(certificate, revoked);
        CertificateRenewalLocation completed = seeder.seedLocationRenewal(certificate, web, revoked);
        completed.setCompletedAt(Instant.now().minus(Duration.ofDays(1)));
        renewalLocationRepository.save(completed);

        // when
        action.perform(certificate, trigger);

        // then
        CertificateRenewalLocation row = seeder.locationRow(certificate, web);
        assertThat(row.getCompletedAt()).isNull();
        assertThat(row.getSuccessorUuid()).isNull();
        assertThat(row.getAttempt()).isEqualTo(1);
        assertThat(row.getNotBefore()).isNull();
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewAt()).isNull();
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .anyMatch(message -> message.contains("%s was revoked".formatted(revoked.getUuid())));
        assertThat(dueForRenewalEvent()).containsExactly(certificate.getUuid());
        verifyRenewals(web, 0);
    }

    @Test
    void recordsThatRenewalStopsAfterTheReopen_whenTheRevokedSuccessorReachesTheAttemptLimit() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate revoked = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REVOKED);
        int maxAttempts = certificate.getRaProfile().getAutoRenewalMaxAttempts();
        CertificateRenewalLocation completed = seeder.seedLocationRenewal(certificate, web, revoked);
        completed.setCompletedAt(Instant.now().minus(Duration.ofDays(1)));
        completed.setAttempt(maxAttempts - 1);
        renewalLocationRepository.save(completed);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(seeder.locationRow(certificate, web).getAttempt()).isEqualTo(maxAttempts);
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .contains("Automatic renewal in location web stopped after %d attempts".formatted(maxAttempts),
                        ("Automatic renewal in location web: the renewed certificate %s was revoked; the attempt limit"
                                + " is reached, so it is not renewed there again (attempt %d of %d)")
                                .formatted(revoked.getUuid(), maxAttempts, maxAttempts));
    }

    @Test
    void raisesTheRenewalDueEvent_whenOneLocationsSuccessorIsRevokedAndAnotherIsIssued() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Location mail = seeder.seedKeyGeneratingLocation(certificate, "mail");
        Certificate issued = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.ISSUED);
        seeder.seedRenewalRelation(certificate, issued);
        Certificate revoked = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REVOKED);
        seeder.seedRenewalRelation(certificate, revoked);
        CertificateRenewalLocation webRow = seeder.seedLocationRenewal(certificate, web, issued);
        webRow.setCompletedAt(Instant.now().minus(Duration.ofDays(1)));
        CertificateRenewalLocation mailRow = seeder.seedLocationRenewal(certificate, mail, revoked);
        mailRow.setCompletedAt(Instant.now().minus(Duration.ofDays(1)));
        renewalLocationRepository.saveAll(List.of(webRow, mailRow));

        // when
        List<UUID> due = dueForRenewalEvent();

        // then
        assertThat(due).containsExactly(certificate.getUuid());
    }

    @Test
    void dropsTheCompletedRow_whenItsSuccessorIsRevokedAndTheLocationNoLongerHoldsTheCertificate() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        Certificate revoked = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REVOKED);
        seeder.seedRenewalRelation(certificate, revoked);
        seeder.seedLocationEntry(web, revoked);
        CertificateRenewalLocation completed = seeder.seedLocationRenewal(certificate, web, revoked);
        completed.setCompletedAt(Instant.now().minus(Duration.ofDays(1)));
        renewalLocationRepository.save(completed);
        certificateLocationRepository.deleteById(new CertificateLocationId(web.getUuid(), certificate.getUuid()));

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(renewalLocationRepository.findByCertificateUuid(certificate.getUuid())).isEmpty();
        verifyRenewals(web, 0);
    }

    @Test
    void pushesTheRenewedCertificateInPlaceOfTheOldOne_whenTheAuthorityIssuesTheLocationRenewalLater()
            throws Exception {
        // given
        Location web = renewInALocationWithAnAuthorityThatIssuesLater();
        Certificate successor = certificateRepository
                .findById(seeder.locationRow(certificate, web).getSuccessorUuid())
                .orElseThrow();
        entityProvider
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(LOCATION_PUSH_PATH))
                        .willReturn(WireMock.okJson("{\"withKey\": true}")));
        V3ConnectorStubs.stubIssueStatusCompleted(laterIssuingAuthority, issuedCertificateData());

        // when
        delivery.pollStatus(successor.getUuid(), CertificateOperation.RENEW);

        // then
        assertThat(certificateRepository.findById(successor.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.ISSUED);
        entityProvider.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PUSH_PATH)));
        assertThat(locationNames(successor)).containsExactly("web");
        assertThat(locationNames(certificate)).isEmpty();
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
    }

    @Test
    void recordsTheFailedPushWithoutCompletingTheLocation_whenTheAuthorityIssuesTheLocationRenewalLater()
            throws Exception {
        // given
        Location web = renewInALocationWithAnAuthorityThatIssuesLater();
        UUID successorUuid = seeder.locationRow(certificate, web).getSuccessorUuid();
        entityProvider
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(LOCATION_PUSH_PATH))
                        .willReturn(WireMock.jsonResponse("{\"message\": \"location is offline\"}", 400)));
        V3ConnectorStubs.stubIssueStatusCompleted(laterIssuingAuthority, issuedCertificateData());

        // when
        delivery.pollStatus(successorUuid, CertificateOperation.RENEW);

        // then
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .anyMatch(message -> message
                        .startsWith("The renewed certificate %s was issued, but pushing it to location web failed"
                                .formatted(successorUuid)));
        assertThat(locationNames(certificate)).containsExactly("web");
        assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNull();
    }

    @Test
    void pushesTheRekeyedCertificateInPlaceOfTheOldOne_whenTheAuthorityRekeysTheLocationRenewalAtOnce()
            throws Exception {
        // given
        entityProvider = LoopbackWireMock.start();
        authority = LoopbackWireMock.start();
        certificate = seeder.seedDueCertificate(seeder.seedRaProfile(authority));
        Location web = seeder.seedKeyGeneratingLocation(entityProvider, certificate, "web");
        Certificate successor = seeder.seedRequestedSuccessor(certificate);
        seeder.seedLocationEntry(web, successor);
        authority
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(AUTHORITY_RENEW_PATH))
                        .willReturn(WireMock.okJson("{ \"certificateData\": \"" + issuedCertificateData() + "\" }")));
        entityProvider
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(LOCATION_PUSH_PATH))
                        .willReturn(WireMock.okJson("{\"withKey\": true}")));
        ClientCertificateRekeyRequestDto inLocation = ClientCertificateRekeyRequestDto.builder().build();
        inLocation.setReplaceInLocations(false);

        // when
        clientOperationService.rekeyCertificateAction(successor.getUuid(), inLocation, true);

        // then
        entityProvider.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PUSH_PATH)));
        assertThat(locationNames(successor)).containsExactly("web");
        assertThat(locationNames(certificate)).isEmpty();
    }

    @Test
    void storesTheFiringOwnerOnTheLocationRow_whenTheRenewalStarts() throws Exception {
        // given
        Location web = seeder.seedKeyGeneratingLocation(certificate, "web");
        stubRenewal(web, CertificateState.PENDING_ISSUE);

        // when
        action.perform(certificate, trigger);

        // then
        assertThat(seeder.locationRow(certificate, web).getOwnerUuid()).isEqualTo(trigger.ownerUuid());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Moves the certificate to an authority that accepts the renewal and issues it later, has the trigger renew it in a
     * key-generating location as a user the auth service knows, lets the authority accept the renewal, and returns the
     * location, which holds both the old certificate and the pending successor.
     */
    private Location renewInALocationWithAnAuthorityThatIssuesLater() throws Exception {
        entityProvider = LoopbackWireMock.start();
        laterIssuingAuthority = LoopbackWireMock.start();
        certificate = seeder.seedDueCertificate(seeder.seedLaterIssuingRaProfile(laterIssuingAuthority));
        Location web = seeder.seedKeyGeneratingLocation(entityProvider, certificate, "web");
        V3ConnectorStubs.stubAttributesAndValidate(laterIssuingAuthority);
        V3ConnectorStubs.stubV3RenewAsync(laterIssuingAuthority);
        authService = AuthServiceWireMockStubs.startImpersonating(trigger.ownerUuid(), "renewal-owner");
        when(locationStub
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(web),
                        eq(certificate.getUuid()), any()))
                .thenAnswer(invocation -> {
                    Certificate successor = new TransactionTemplate(transactionManager,
                            new DefaultTransactionDefinition(TransactionDefinition.PROPAGATION_REQUIRES_NEW))
                            .execute(status -> seeder.seedRequestedSuccessor(certificate));
                    invocation.<Consumer<UUID>>getArgument(3).accept(successor.getUuid());
                    clientOperationService
                            .renewCertificateAction(successor.getUuid(),
                                    ClientCertificateRenewRequestDto.builder().build(), true);
                    seeder.seedLocationEntry(web, successor);
                    return successor.getUuid();
                });
        action.perform(certificate, trigger);
        return web;
    }

    private String issuedCertificateData() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream stream = getClass().getClassLoader().getResourceAsStream("client1.p12")) {
            keyStore.load(stream, "123456".toCharArray());
        }
        return Base64.getEncoder().encodeToString(keyStore.getCertificate("1").getEncoded());
    }

    private List<String> locationNames(Certificate owner) {
        return new TransactionTemplate(transactionManager)
                .execute(status -> certificateLocationRepository
                        .findByCertificateUuid(owner.getUuid())
                        .stream()
                        .map(entry -> entry.getLocation().getName())
                        .toList());
    }

    /**
     * Fires the action as the event handling does, inside a transaction that has written the firing's history, and
     * hands out the firing before the action runs.
     */
    private void fireInEvent(AtomicReference<UUID> firingUuid) {
        AutoRenewalAfterCommit afterCommit = new AutoRenewalAfterCommit(action, triggerService, transactionManager);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            TriggerAssociation association = seeder.seedRenewTrigger(trigger.ownerUuid());
            TriggerHistory firing = triggerService
                    .createTriggerHistory(association.getTriggerUuid(), association, certificate.getUuid(), null, null,
                            Resource.CERTIFICATE);
            entityManager.flush();
            firingUuid.set(firing.getUuid());
            try {
                afterCommit
                        .perform(certificate, new TriggerContext(association.getTriggerUuid(), trigger.ownerUuid(),
                                firing.getUuid(), null));
            } catch (RuleException e) {
                throw new AssertionError("The renewal failed", e);
            }
        });
    }

    /** Whether another connection sees the firing's history, which only a committed event transaction makes visible. */
    private boolean isCommitted(UUID firingUuid) throws Exception {
        return CompletableFuture
                .supplyAsync(() -> triggerHistoryRepository.existsById(firingUuid))
                .get(1, TimeUnit.MINUTES);
    }

    /** The certificates the renewal-due event would be raised for, among the one under test. */
    private List<UUID> dueForRenewalEvent() {
        return certificateRepository
                .findUuidsUsingSecurityFilter(SecurityFilter.create(),
                        (root, cb, cr) -> cb
                                .and(RenewalEligibility.awaitingRenewalOrLocationRenewal(root, cb, cr),
                                        cb.equal(root.get(Certificate_.uuid), certificate.getUuid())),
                        null, null);
    }

    /**
     * Answers as {@link #stubRenewal} does, and as the location service does: the successor takes the place of the
     * certificate in the location, which then no longer holds it.
     */
    private Certificate stubReplacingRenewal(Location location, CertificateState successorState) throws Exception {
        Certificate successor = seeder.seedSuccessor(certificate.getRaProfile(), successorState);
        when(locationStub
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(location),
                        eq(certificate.getUuid()), any()))
                .thenAnswer(invocation -> {
                    requestRenewal(successor, invocation.getArgument(3));
                    seeder.seedLocationEntry(location, successor);
                    certificateLocationRepository
                            .deleteById(new CertificateLocationId(location.getUuid(), certificate.getUuid()));
                    return successor.getUuid();
                });
        return successor;
    }

    /**
     * Answers as the location service does: the successor and its renewal relation are committed and handed to the
     * caller before the renewal is queued, then the successor is linked to the location.
     */
    private Certificate stubRenewal(Location location, CertificateState successorState) throws Exception {
        Certificate successor = seeder.seedSuccessor(certificate.getRaProfile(), successorState);
        when(locationStub
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(location),
                        eq(certificate.getUuid()), any()))
                .thenAnswer(invocation -> {
                    requestRenewal(successor, invocation.getArgument(3));
                    seeder.seedLocationEntry(location, successor);
                    return successor.getUuid();
                });
        return successor;
    }

    /** Requests the renewal as the location service does, then fails while linking the successor to the location. */
    private Certificate stubFailureAfterRequest(Location location) throws Exception {
        Certificate successor = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.PENDING_ISSUE);
        when(locationStub
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(location),
                        eq(certificate.getUuid()), any()))
                .thenAnswer(invocation -> {
                    requestRenewal(successor, invocation.getArgument(3));
                    throw new LocationException("Failed to add the new certificate to the location");
                });
        return successor;
    }

    /** Commits the renewal relation on its own, as the location service does before it dispatches the renewal. */
    private void requestRenewal(Certificate successor, Consumer<UUID> beforeDispatch) {
        new TransactionTemplate(transactionManager,
                new DefaultTransactionDefinition(TransactionDefinition.PROPAGATION_REQUIRES_NEW))
                .executeWithoutResult(status -> seeder.seedRenewalRelation(certificate, successor));
        beforeDispatch.accept(successor.getUuid());
    }

    private void stubFailure(Location location) throws Exception {
        when(locationStub
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(location),
                        eq(certificate.getUuid()), any()))
                .thenThrow(new LocationException("location generated no request"));
    }

    private void verifyRenewals(Location location, int times) throws Exception {
        verify(locationStub, times == 0 ? never() : times(times))
                .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class), inLocation(location),
                        eq(certificate.getUuid()), any());
    }

    private void issue(Certificate successor) {
        successor.setState(CertificateState.ISSUED);
        certificateRepository.save(successor);
    }

    private void endBackoff(CertificateRenewalLocation row) {
        row.setNotBefore(Instant.now().minus(Duration.ofMinutes(1)));
        renewalLocationRepository.save(row);
    }

    private List<CertificateEventHistory> renewHistory() {
        return eventHistoryRepository
                .findByCertificateOrderByCreatedDesc(certificate)
                .stream()
                .filter(entry -> entry.getEvent() == CertificateEvent.RENEW)
                .toList();
    }

    private static SecuredUUID inLocation(Location location) {
        return argThat(locationUuid -> locationUuid != null && location.getUuid().equals(locationUuid.getValue()));
    }

    private static void assertStarted(CertificateRenewalLocation row, Certificate successor) {
        assertThat(row.getSuccessorUuid()).isEqualTo(successor.getUuid());
        assertThat(row.getStartedAt()).isNull();
        assertThat(row.getCompletedAt()).isNull();
    }
}
