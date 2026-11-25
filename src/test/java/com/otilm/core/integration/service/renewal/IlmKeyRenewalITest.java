package com.otilm.core.integration.service.renewal;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.workflows.Execution;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.entity.workflows.TriggerHistoryRecord;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.workflows.ExecutionRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRecordRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.renewal.auto.AsyncRenewalLocationReplacer;
import com.otilm.core.service.renewal.auto.AutoRenewalAction;
import com.otilm.core.service.renewal.auto.IlmKeyRenewalHandler;
import com.otilm.core.service.renewal.auto.TriggerContext;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.seeders.AutoRenewalSeeder;
import jakarta.persistence.EntityManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.OngoingStubbing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IlmKeyRenewalITest extends BaseSpringBootTest {

    private static final String AUTHORITY_RENEW_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/renew";
    private static final String LOCATION_PATH = "/v1/entityProvider/entities/[^/]+/locations";
    private static final long WAIT_SECONDS = 60;

    @Autowired
    private AutoRenewalSeeder seeder;
    @Autowired
    private CertificateTypeHandlerRegistry typeHandlerRegistry;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateLocationRepository certificateLocationRepository;
    @Autowired
    private CertificateEventHistoryInternalService eventHistoryService;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired
    private TriggerInternalService triggerService;
    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;
    @Autowired
    private TriggerHistoryRecordRepository triggerHistoryRecordRepository;
    @Autowired
    private ExecutionRepository executionRepository;
    @Autowired
    private ClientOperationInternalService clientOperationService;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private QueuedMessageDelivery delivery;
    @Autowired
    private AsyncRenewalLocationReplacer locationReplacer;

    private final ClientOperationInternalService renewalStub = mock(ClientOperationInternalService.class);
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final WireMockServer mockServer = new WireMockServer(LoopbackWireMock.options());
    private RaProfile raProfile;
    private Certificate certificate;
    private AutoRenewalAction action;
    private TriggerContext trigger;
    private WireMockServer laterIssuingAuthority;
    private WireMockServer authService;

    @BeforeEach
    void seedDueCertificate() {
        mockServer.start();
        raProfile = seeder.seedRaProfile(mockServer);
        certificate = seeder.seedDueHeldKeyCertificate(raProfile);
        IlmKeyRenewalHandler handler = new IlmKeyRenewalHandler(renewalStub, renewalInfoRepository, entityManager,
                transactionManager);
        action = new AutoRenewalAction(renewalInfoRepository, certificateRepository, eventHistoryService, entityManager,
                transactionManager, typeHandlerRegistry, List.of(handler));
        trigger = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), null, null);
    }

    @AfterEach
    void stop() {
        executor.shutdownNow();
        mockServer.stop();
        if (laterIssuingAuthority != null) {
            laterIssuingAuthority.stop();
        }
        if (authService != null) {
            authService.stop();
        }
    }

    @Test
    void renewsOnceWithoutARequest_whenTheRenewalIsDue() throws Exception {
        // given
        ArgumentCaptor<ClientCertificateRenewRequestDto> request = ArgumentCaptor
                .forClass(ClientCertificateRenewRequestDto.class);
        AtomicReference<Certificate> successor = stubRenewal();

        // when
        fire();

        // then
        verify(renewalStub)
                .renewCertificate(argThat(
                        authority -> raProfile.getAuthorityInstanceReferenceUuid().equals(authority.getValue())),
                        argThat(profile -> raProfile.getUuid().equals(profile.getValue())),
                        eq(certificate.getUuid().toString()), request.capture(), isNull(), any());
        assertThat(request.getValue().getRequest()).isNull();
        assertThat(request.getValue().isReplaceInLocations()).isTrue();
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewSuccessorUuid()).isEqualTo(successor.get().getUuid());
        assertThat(row.getRenewStartedAt()).isNull();
        assertThat(row.getRenewAttempt()).isZero();
    }

    @Test
    void callsTheRenewalOutsideAnyTransaction_whenTheTriggerEvaluationRunsInOne() throws Exception {
        // given
        AtomicBoolean transactionActiveDuringRenewal = new AtomicBoolean(true);
        whenRenewed().thenAnswer(invocation -> {
            transactionActiveDuringRenewal.set(TransactionSynchronizationManager.isActualTransactionActive());
            Certificate successor = requestRenewal(invocation.getArgument(5));
            ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
            response.setUuid(successor.getUuid().toString());
            return response;
        });

        // when
        Throwable failed = fireInsideTransaction();

        // then
        assertThat(failed).isNull();
        assertThat(transactionActiveDuringRenewal).isFalse();
        verifyRenewals(1);
    }

    @Test
    void replacesTheOldCertificateInBothLocations_whenTheRenewalIsIssued() throws Exception {
        // given
        seeder.seedPushOnlyLocations(mockServer, certificate, "web", "mail");
        AtomicReference<Certificate> successor = stubRenewal();
        stubAuthorityRenewing();
        stubLocationAnswering("remove", WireMock.okJson("{}"));
        stubLocationAnswering("push", WireMock.okJson("{\"withKey\": false}"));
        fire();

        // when
        clientOperationService.renewCertificateAction(successor.get().getUuid(), renewRequest(), true);

        // then
        assertThat(locationNames(successor.get())).containsExactlyInAnyOrder("web", "mail");
        assertThat(locationNames(certificate)).isEmpty();
    }

    @Test
    void replacesTheOldCertificateInBothLocations_whenTheAuthorityIssuesTheRenewalLater() throws Exception {
        // given
        Certificate successor = requestRenewalFromAnAuthorityThatIssuesLater();
        stubLocationAnswering("remove", WireMock.okJson("{}"));
        stubLocationAnswering("push", WireMock.okJson("{\"withKey\": false}"));
        V3ConnectorStubs.stubIssueStatusCompleted(laterIssuingAuthority, issuedCertificateData());

        // when
        delivery.pollStatus(successor.getUuid(), CertificateOperation.RENEW);

        // then
        assertThat(certificateRepository.findById(successor.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.ISSUED);
        assertThat(locationNames(successor)).containsExactlyInAnyOrder("web", "mail");
        assertThat(locationNames(certificate)).isEmpty();
    }

    @Test
    void replacesTheOldCertificateAsTheFiringOwner_whenTheTriggerAssociationWasRemovedBeforeTheRenewalIssued()
            throws Exception {
        // given
        Certificate successor = requestRenewalFromAnAuthorityThatIssuesLater();
        removeTriggerAssociationOf(seeder.renewalRow(certificate.getUuid()).getRenewTriggerHistoryUuid());
        stubLocationAnswering("remove", WireMock.okJson("{}"));
        stubLocationAnswering("push", WireMock.okJson("{\"withKey\": false}"));
        V3ConnectorStubs.stubIssueStatusCompleted(laterIssuingAuthority, issuedCertificateData());

        // when
        delivery.pollStatus(successor.getUuid(), CertificateOperation.RENEW);

        // then
        assertThat(locationNames(successor)).containsExactlyInAnyOrder("web", "mail");
        assertThat(locationNames(certificate)).isEmpty();
    }

    @Test
    void storesTheFiringOwnerWithTheSuccessor_whenTheRenewalIsRequested() throws Exception {
        // given
        stubRenewal();

        // when
        fire();

        // then
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewOwnerUuid()).isEqualTo(trigger.ownerUuid());
    }

    @Test
    void recordsTheFailedPushOnceWithoutRenewingAgain_whenTheAuthorityIssuesTheRenewalLater() throws Exception {
        // given
        Certificate successor = requestRenewalFromAnAuthorityThatIssuesLater();
        stubLocationAnswering("remove", WireMock.jsonResponse("{\"message\": \"location is offline\"}", 400));
        V3ConnectorStubs.stubIssueStatusCompleted(laterIssuingAuthority, issuedCertificateData());
        delivery.pollStatus(successor.getUuid(), CertificateOperation.RENEW);

        // when
        Throwable next = fire();

        // then
        String expected = ("The renewed certificate %s was issued, but replacing the old certificate in its locations"
                + " failed and is not retried").formatted(successor.getUuid());
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .filteredOn(message -> message.startsWith(expected))
                .singleElement()
                .asString()
                .contains("The renewed certificate is in no location; the old certificate is still in mail, web");
        assertThat(triggerHistoryRecordRepository.findAll())
                .singleElement()
                .satisfies(historyRecord -> assertThat(historyRecord.getMessage()).startsWith(expected));
        assertThat(next).isNull();
        verifyRenewals(1);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewAttempt()).isZero();
        assertThat(row.getRenewSuccessorUuid()).isEqualTo(successor.getUuid());
    }

    @Test
    void reopensTheRenewal_whenTheIssuedSuccessorIsRevoked() throws Exception {
        // given
        Certificate revoked = seedRevokedSuccessor();

        // when
        Throwable firing = fire();

        // then
        assertThat(firing).isNull();
        verifyRenewals(0);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewSuccessorUuid()).isNull();
        assertThat(row.getRenewAt()).isNull();
        assertThat(row.getRenewAttempt()).isEqualTo(1);
        assertThat(row.getRenewNotBefore()).isNull();
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .anyMatch(message -> message.contains("%s was revoked".formatted(revoked.getUuid())));
    }

    @Test
    void recordsThatRenewalStops_whenTheRevokedSuccessorReachesTheAttemptLimit() throws Exception {
        // given
        Certificate revoked = seedRevokedSuccessor();
        int maxAttempts = raProfile.getAutoRenewalMaxAttempts();
        CertificateRenewalInfo atLastAttempt = seeder.renewalRow(certificate.getUuid());
        atLastAttempt.setRenewAttempt(maxAttempts - 1);
        renewalInfoRepository.save(atLastAttempt);

        // when
        fire();

        // then
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewAttempt()).isEqualTo(maxAttempts);
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .contains(
                        "The renewed certificate %s was revoked; the attempt limit is reached, so it is not renewed again (attempt %d of %d)"
                                .formatted(revoked.getUuid(), maxAttempts, maxAttempts))
                .noneMatch(message -> message.contains("is renewed again"));
    }

    @Test
    void recordsThatRenewalStops_whenTheAttemptLimitWasLoweredBelowTheStoredCount() throws Exception {
        // given
        Certificate revoked = seedRevokedSuccessor();
        int maxAttempts = raProfile.getAutoRenewalMaxAttempts();
        CertificateRenewalInfo pastTheLimit = seeder.renewalRow(certificate.getUuid());
        pastTheLimit.setRenewAttempt(maxAttempts + 2);
        renewalInfoRepository.save(pastTheLimit);

        // when
        fire();

        // then
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .anyMatch(message -> message
                        .startsWith("The renewed certificate %s was revoked; the attempt limit is reached"
                                .formatted(revoked.getUuid())))
                .noneMatch(message -> message.contains("is renewed again"));
    }

    @Test
    void renewsAgain_whenTheReopenedRenewalIsDueDespiteTheRevokedSuccessorsRelation() throws Exception {
        // given
        seedRevokedSuccessor();
        fire();
        CertificateRenewalInfo reopened = seeder.renewalRow(certificate.getUuid());
        reopened.setRenewAt(Instant.now().minus(Duration.ofMinutes(1)));
        renewalInfoRepository.save(reopened);
        AtomicReference<Certificate> successor = stubRenewal();

        // when
        Throwable firing = fire();

        // then
        assertThat(firing).isNull();
        verifyRenewals(1);
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewSuccessorUuid())
                .isEqualTo(successor.get().getUuid());
    }

    @Test
    void replacesNothingAgain_whenTheRenewalIssuedAtOnceHasReplacedTheOldCertificate() throws Exception {
        // given
        seeder.seedPushOnlyLocations(mockServer, certificate, "web", "mail");
        AtomicReference<Certificate> successor = stubRenewal();
        stubAuthorityRenewing();
        stubLocationAnswering("remove", WireMock.okJson("{}"));
        stubLocationAnswering("push", WireMock.okJson("{\"withKey\": false}"));
        fire();
        clientOperationService.renewCertificateAction(successor.get().getUuid(), renewRequest(), true);

        // when
        locationReplacer.replaceInLocations(successor.get().getUuid());

        // then
        mockServer.verify(2, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PATH + "/remove")));
        mockServer.verify(2, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PATH + "/push")));
        assertThat(locationNames(successor.get())).containsExactlyInAnyOrder("web", "mail");
    }

    @Test
    void recordsEachRemovalOnce_whenTheRenewalReplacesTheOldCertificateInItsLocations() throws Exception {
        // given
        Certificate successor = requestRenewalReplacingInWebAndMail();

        // when
        clientOperationService.renewCertificateAction(successor.getUuid(), renewRequest(), true);

        // then
        assertThat(findLocationHistory(certificate))
                .extracting(CertificateEventHistory::getMessage)
                .containsExactlyInAnyOrder("Removed from Location web", "Removed from Location mail");
    }

    @Test
    void recordsEachPushOnce_whenTheRenewalReplacesTheOldCertificateInItsLocations() throws Exception {
        // given
        Certificate successor = requestRenewalReplacingInWebAndMail();

        // when
        clientOperationService.renewCertificateAction(successor.getUuid(), renewRequest(), true);

        // then
        assertThat(findLocationHistory(successor))
                .extracting(CertificateEventHistory::getMessage)
                .containsExactlyInAnyOrder("Pushed to Location web", "Pushed to Location mail");
    }

    @Test
    void startsNoSecondRenewal_whileTheSuccessorIsPending() throws Exception {
        // given
        AtomicReference<Certificate> successor = stubRenewal();
        fire();

        // when
        Throwable second = fire();

        // then
        assertThat(second).isNull();
        verifyRenewals(1);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewSuccessorUuid()).isEqualTo(successor.get().getUuid());
        assertThat(row.getRenewAttempt()).isZero();
    }

    @Test
    void countsOneAttemptAndBacksOff_whenTheSuccessorIsRejected() throws Exception {
        // given
        AtomicReference<Certificate> successor = stubRenewal();
        fire();
        reject(successor.get());
        Instant before = Instant.now();

        // when
        Throwable found = fire();
        Throwable later = fire();

        // then
        assertThat(found).isInstanceOf(RuleException.class).hasMessageContaining("rejected");
        assertThat(later).isNull();
        verifyRenewals(1);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewAttempt()).isEqualTo(1);
        assertThat(row.getRenewNotBefore()).isAfterOrEqualTo(before.plus(Duration.ofHours(1)));
        assertThat(row.getRenewSuccessorUuid()).isNull();
    }

    @Test
    void recordsTheFailedPushWithoutRenewingAgain_whenReplacingInTheLocationsFails() throws Exception {
        // given
        seeder.seedPushOnlyLocations(mockServer, certificate, "web", "mail");
        TriggerHistory firing = seedFiring();
        AtomicReference<Certificate> successor = stubRenewal();
        stubAuthorityRenewing();
        stubLocationAnswering("remove", WireMock.jsonResponse("{\"message\": \"location is offline\"}", 400));
        fire();
        UUID successorUuid = successor.get().getUuid();

        // when
        assertThatThrownBy(() -> clientOperationService.renewCertificateAction(successorUuid, renewRequest(), true))
                .isInstanceOf(CertificateOperationException.class);
        Throwable next = fire();

        // then
        String expected = ("The renewed certificate %s was issued, but replacing the old certificate in its locations"
                + " failed and is not retried").formatted(successorUuid);
        assertThat(renewHistory())
                .extracting(CertificateEventHistory::getMessage)
                .filteredOn(message -> message.startsWith(expected))
                .singleElement()
                .asString()
                .contains("The renewed certificate is in no location; the old certificate is still in mail, web");
        List<TriggerHistoryRecord> records = triggerHistoryRecordRepository.findAll();
        assertThat(records).singleElement().satisfies(historyRecord -> {
            assertThat(historyRecord.getTriggerHistoryUuid()).isEqualTo(firing.getUuid());
            assertThat(historyRecord.getExecutionUuid()).isEqualTo(trigger.executionUuid());
            assertThat(historyRecord.getMessage()).startsWith(expected);
        });
        assertThat(triggerHistoryRepository.findById(firing.getUuid()).orElseThrow().isActionsPerformed()).isFalse();
        assertThat(next).isNull();
        verifyRenewals(1);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewAttempt()).isZero();
        assertThat(row.getRenewSuccessorUuid()).isEqualTo(successorUuid);
    }

    @Test
    void keepsTheSuccessorWithoutCountingAnAttempt_whenTheRenewalFailsAfterItWasRequested() throws Exception {
        // given
        AtomicReference<Certificate> successor = new AtomicReference<>();
        whenRenewed().thenAnswer(invocation -> {
            successor.set(requestRenewal(invocation.getArgument(5)));
            throw new CertificateOperationException("queuing the renewal failed");
        });

        // when
        Throwable failed = fire();
        Throwable next = fire();

        // then
        assertThat(failed).isInstanceOf(RuleException.class).hasMessageContaining("was requested, but");
        assertThat(next).isNull();
        verifyRenewals(1);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewSuccessorUuid()).isEqualTo(successor.get().getUuid());
        assertThat(row.getRenewAttempt()).isZero();
        assertThat(row.getRenewStartedAt()).isNull();
    }

    @Test
    void countsAnAttempt_whenTheRenewalFailsBeforeAnythingWasRequested() throws Exception {
        // given
        whenRenewed().thenThrow(new CertificateOperationException("the authority refused the request"));

        // when
        Throwable failed = fire();

        // then
        assertThat(failed).isInstanceOf(RuleException.class).hasMessageContaining("the authority refused the request");
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        assertThat(row.getRenewAttempt()).isEqualTo(1);
        assertThat(row.getRenewSuccessorUuid()).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Answers as Core does: the successor and its pending relation are committed in their own transaction, the caller
     * sees the successor before the renewal is queued, and the call returns the successor.
     */
    private AtomicReference<Certificate> stubRenewal() throws Exception {
        AtomicReference<Certificate> successor = new AtomicReference<>();
        whenRenewed().thenAnswer(invocation -> {
            successor.set(requestRenewal(invocation.getArgument(5)));
            ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
            response.setUuid(successor.get().getUuid().toString());
            return response;
        });
        return successor;
    }

    private OngoingStubbing<ClientCertificateDataResponseDto> whenRenewed() throws Exception {
        return when(renewalStub
                .renewCertificate(any(SecuredParentUUID.class), any(SecuredUUID.class),
                        eq(certificate.getUuid().toString()), any(ClientCertificateRenewRequestDto.class), isNull(),
                        any()));
    }

    private Certificate requestRenewal(Consumer<UUID> beforeDispatch) {
        TransactionTemplate own = new TransactionTemplate(transactionManager);
        own.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        Certificate successor = own.execute(status -> seeder.seedRequestedSuccessor(certificate));
        beforeDispatch.accept(successor.getUuid());
        return successor;
    }

    /** Fires the action on another thread and fails, instead of hanging, when it waits for a lock too long. */
    private Throwable fire() throws Exception {
        Future<Throwable> firing = executor.submit(() -> {
            try {
                action.perform(certificate, trigger);
                return null;
            } catch (RuleException e) {
                return e;
            }
        });
        try {
            return firing.get(WAIT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            new TransactionTemplate(transactionManager)
                    .executeWithoutResult(status -> entityManager
                            .createNativeQuery("SELECT pg_cancel_backend(pid) FROM pg_stat_activity"
                                    + " WHERE wait_event_type = 'Lock' AND pid <> pg_backend_pid()")
                            .getResultList());
            firing.cancel(true);
            throw new AssertionError("The renewal waited for a lock", e);
        }
    }

    /** Fires the action inside a transaction of the caller, as the trigger evaluation does. */
    private Throwable fireInsideTransaction() throws Exception {
        return executor.submit(() -> new TransactionTemplate(transactionManager).execute(status -> {
            try {
                action.perform(certificate, trigger);
                return null;
            } catch (RuleException e) {
                return e;
            }
        })).get(WAIT_SECONDS, TimeUnit.SECONDS);
    }

    private TriggerHistory seedFiring() {
        TriggerAssociation association = seeder.seedRenewTrigger(UUID.randomUUID());
        UUID executionUuid = executionRepository
                .findAll()
                .stream()
                .filter(execution -> execution.getType() == ExecutionType.RENEW_CERTIFICATE)
                .map(Execution::getUuid)
                .findFirst()
                .orElseThrow();
        TriggerHistory history = triggerService
                .createTriggerHistory(association.getTriggerUuid(), association, certificate.getUuid(), null, null,
                        Resource.CERTIFICATE);
        history.setActionsPerformed(true);
        history = triggerHistoryRepository.save(history);
        trigger = new TriggerContext(association.getTriggerUuid(), association.getTriggeredBy(), history.getUuid(),
                executionUuid);
        return history;
    }

    /** Deletes the association the firing ran under, which the database detaches from the firing's history. */
    private void removeTriggerAssociationOf(UUID firingUuid) {
        UUID associationUuid = triggerHistoryRepository.findById(firingUuid).orElseThrow().getTriggerAssociationUuid();
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            entityManager
                    .createNativeQuery("UPDATE trigger_history SET trigger_association_uuid = NULL WHERE uuid = :uuid")
                    .setParameter("uuid", firingUuid)
                    .executeUpdate();
            entityManager
                    .createNativeQuery("DELETE FROM trigger_association WHERE uuid = :uuid")
                    .setParameter("uuid", associationUuid)
                    .executeUpdate();
        });
    }

    private void stubAuthorityRenewing() throws Exception {
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(AUTHORITY_RENEW_PATH))
                        .willReturn(WireMock.okJson("{ \"certificateData\": \"" + issuedCertificateData() + "\" }")));
    }

    private String issuedCertificateData() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream stream = getClass().getClassLoader().getResourceAsStream("client1.p12")) {
            keyStore.load(stream, "123456".toCharArray());
        }
        return Base64.getEncoder().encodeToString(keyStore.getCertificate("1").getEncoded());
    }

    /**
     * Moves the certificate to an authority that accepts the renewal and issues it later, has a trigger owned by a user
     * the auth service knows renew it while it is in two locations, and returns the successor the authority accepted.
     */
    private Certificate requestRenewalFromAnAuthorityThatIssuesLater() throws Exception {
        laterIssuingAuthority = LoopbackWireMock.start();
        raProfile = seeder.seedLaterIssuingRaProfile(laterIssuingAuthority);
        certificate = seeder.seedDueHeldKeyCertificate(raProfile);
        seeder.seedPushOnlyLocations(mockServer, certificate, "web", "mail");
        V3ConnectorStubs.stubAttributesAndValidate(laterIssuingAuthority);
        V3ConnectorStubs.stubV3RenewAsync(laterIssuingAuthority);
        seedFiring();
        authService = AuthServiceWireMockStubs.startImpersonating(trigger.ownerUuid(), "renewal-owner");
        AtomicReference<Certificate> successor = stubRenewal();
        fire();
        clientOperationService.renewCertificateAction(successor.get().getUuid(), renewRequest(), true);
        return successor.get();
    }

    private void stubLocationAnswering(String operation, ResponseDefinitionBuilder answer) {
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching(LOCATION_PATH + "/" + operation)).willReturn(answer));
        for (String attributes : List.of("/push/attributes", "/csr/attributes")) {
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(LOCATION_PATH + attributes))
                            .willReturn(WireMock.okJson("[]")));
        }
    }

    private static ClientCertificateRenewRequestDto renewRequest() {
        ClientCertificateRenewRequestDto request = ClientCertificateRenewRequestDto.builder().build();
        request.setReplaceInLocations(true);
        return request;
    }

    /** Rejects the successor as Core does: its state changes and its relation to the predecessor is deleted. */
    private void reject(Certificate successor) {
        Certificate stored = certificateRepository.findById(successor.getUuid()).orElseThrow();
        stored.setState(CertificateState.REJECTED);
        certificateRepository.save(stored);
        certificateRelationRepository
                .findAll()
                .stream()
                .filter(relation -> relation.getId().getSuccessorCertificateUuid().equals(successor.getUuid()))
                .forEach(certificateRelationRepository::delete);
    }

    private List<String> locationNames(Certificate owner) {
        return new TransactionTemplate(transactionManager)
                .execute(status -> certificateLocationRepository
                        .findByCertificateUuid(owner.getUuid())
                        .stream()
                        .map(entry -> entry.getLocation().getName())
                        .toList());
    }

    private void verifyRenewals(int count) throws Exception {
        verify(renewalStub, times(count))
                .renewCertificate(any(SecuredParentUUID.class), any(SecuredUUID.class),
                        eq(certificate.getUuid().toString()), any(ClientCertificateRenewRequestDto.class), isNull(),
                        any());
    }

    private Certificate requestRenewalReplacingInWebAndMail() throws Exception {
        seeder.seedPushOnlyLocations(mockServer, certificate, "web", "mail");
        AtomicReference<Certificate> successor = stubRenewal();
        stubAuthorityRenewing();
        stubLocationAnswering("remove", WireMock.okJson("{}"));
        stubLocationAnswering("push", WireMock.okJson("{\"withKey\": false}"));
        fire();
        return successor.get();
    }

    private List<CertificateEventHistory> findLocationHistory(Certificate owner) {
        return eventHistoryRepository
                .findByCertificateOrderByCreatedDesc(owner)
                .stream()
                .filter(entry -> entry.getEvent() == CertificateEvent.UPDATE_LOCATION)
                .toList();
    }

    /** A successor this certificate's automatic renewal started, issued and then revoked. */
    private Certificate seedRevokedSuccessor() {
        Certificate revoked = seeder.seedSuccessor(raProfile, CertificateState.REVOKED);
        seeder.seedRenewalRelation(certificate, revoked);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        row.setRenewSuccessorUuid(revoked.getUuid());
        renewalInfoRepository.save(row);
        return revoked;
    }

    private List<CertificateEventHistory> renewHistory() {
        return eventHistoryRepository
                .findByCertificateOrderByCreatedDesc(certificate)
                .stream()
                .filter(entry -> entry.getEvent() == CertificateEvent.RENEW)
                .toList();
    }
}
