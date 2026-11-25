package com.otilm.core.integration.service.renewal;

import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.entity.workflows.TriggerHistoryRecord;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRecordRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.service.renewal.auto.AutoRenewalAction;
import com.otilm.core.service.renewal.auto.AutoRenewalModeResolver;
import com.otilm.core.service.renewal.auto.TriggerContext;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.AutoRenewalSeeder;
import jakarta.persistence.EntityManager;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AutoRenewalActionITest extends BaseSpringBootTest {

    private static final long EVALUATION_TIMEOUT_SECONDS = 60;

    @Autowired
    private AutoRenewalSeeder seeder;
    @Autowired
    private CertificateTypeHandlerRegistry typeHandlerRegistry;
    @Autowired
    private CertificateTriggerEvaluator certificateTriggerEvaluator;
    @Autowired
    private TriggerInternalService triggerService;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private TransactionTemplate transactionTemplate;
    @Autowired
    private CertificateEventHistoryInternalService eventHistoryService;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private TriggerHistoryRecordRepository triggerHistoryRecordRepository;

    @Test
    void skipsWithoutARecord_whenAutomaticRenewalIsDisabled() throws Exception {
        // given
        RaProfile disabled = seeder.seedRaProfile(false);
        Certificate certificate = seeder.seedDueHeldKeyCertificate(disabled);
        TriggerAssociation association = seeder.seedRenewTrigger(UUID.randomUUID());

        // when
        TriggerHistory history = fire(association, certificate);

        // then
        assertThat(recordsOf(history)).isEmpty();
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewStartedAt()).isNull();
        assertThat(renewHistory(certificate)).isEmpty();
    }

    @Test
    void skipsWithoutARecord_whenTheRenewalTimeIsNotReached() throws Exception {
        // given
        Certificate certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
        Instant later = Instant.now().plus(Duration.ofHours(3)).truncatedTo(ChronoUnit.MILLIS);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        row.setRenewAt(later);
        renewalInfoRepository.save(row);
        TriggerAssociation association = seeder.seedRenewTrigger(UUID.randomUUID());

        // when
        TriggerHistory history = fire(association, certificate);

        // then
        assertThat(recordsOf(history)).isEmpty();
        CertificateRenewalInfo stored = seeder.renewalRow(certificate.getUuid());
        assertThat(stored.getRenewAt()).isEqualTo(later);
        assertThat(stored.getRenewStartedAt()).isNull();
    }

    @Test
    void writesTheBlockedReasonOnce_whenACertificateThatCannotBeRenewedFiresThreeTimes() throws Exception {
        // given
        Certificate certificate = seeder.seedDueCertificate(seeder.seedRaProfile(true));
        TriggerAssociation association = seeder.seedRenewTrigger(UUID.randomUUID());

        // when
        List<TriggerHistory> histories = List
                .of(fire(association, certificate), fire(association, certificate), fire(association, certificate));

        // then
        assertThat(histories).isNotEmpty().allSatisfy(history -> assertThat(recordsOf(history)).isEmpty());
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewBlockedReason())
                .isEqualTo(AutoRenewalModeResolver.NO_KEY);
        assertThat(renewHistory(certificate))
                .singleElement()
                .extracting(CertificateEventHistory::getMessage)
                .asString()
                .contains(AutoRenewalModeResolver.NO_KEY);
    }

    @Test
    void recordsTheBlockedReasonWithoutCountingAnAttempt_whenTheCertificateTypeDoesNotSupportRenewal()
            throws Exception {
        // given
        Certificate certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
        var typeWithoutHandler = new CertificateTypeHandlerRegistry(List.of());
        AutoRenewalAction action = new AutoRenewalAction(renewalInfoRepository, certificateRepository,
                eventHistoryService, entityManager, transactionManager, typeWithoutHandler, List.of());
        TriggerContext trigger = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), null, null);

        // when
        action.perform(certificate, trigger);

        // then
        CertificateRenewalInfo stored = seeder.renewalRow(certificate.getUuid());
        assertThat(stored.getRenewBlockedReason()).isEqualTo(AutoRenewalModeResolver.RENEWAL_NOT_SUPPORTED);
        assertThat(stored.getRenewStartedAt()).isNull();
    }

    @Test
    void recordsAFailure_whenTheTriggerHasNoOwner() throws Exception {
        // given
        Certificate certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
        TriggerAssociation ownerless = seeder.seedRenewTrigger(null);

        // when
        TriggerHistory history = fire(ownerless, certificate);

        // then
        assertThat(recordsOf(history))
                .singleElement()
                .extracting(TriggerHistoryRecord::getMessage)
                .asString()
                .contains("no owner");
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewStartedAt()).isNull();
    }

    @Test
    void recordsAFailureWithoutCountingAnAttempt_whenNoHandlerServesTheMode() {
        // given
        Certificate certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
        AutoRenewalAction withoutHandlers = new AutoRenewalAction(renewalInfoRepository, certificateRepository,
                eventHistoryService, entityManager, transactionManager, typeHandlerRegistry, List.of());
        TriggerContext trigger = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), null, null);

        // when
        ThrowingCallable fire = () -> withoutHandlers.perform(certificate, trigger);

        // then
        assertThatThrownBy(fire).isInstanceOf(RuleException.class).hasMessageContaining("not available");
        CertificateRenewalInfo stored = seeder.renewalRow(certificate.getUuid());
        assertThat(stored.getRenewAttempt()).isZero();
        assertThat(stored.getRenewStartedAt()).isNull();
    }

    @Test
    void skipsWithoutWaiting_whenAnEarlierTriggerOfTheSameEvaluationHoldsTheRenewalRow() throws Exception {
        // given
        Certificate certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
        UUID ownerUuid = UUID.randomUUID();
        TriggerAssociation removeRaProfile = seeder.seedRemoveRaProfileTrigger(ownerUuid);
        TriggerAssociation renew = seeder.seedRenewTrigger(ownerUuid);
        SecurityContext callerContext = SecurityContextHolder.getContext();
        ExecutorService evaluationThread = Executors.newSingleThreadExecutor();

        // when
        Future<List<TriggerHistory>> evaluation = evaluationThread.submit(() -> {
            SecurityContextHolder.setContext(callerContext);
            return transactionTemplate
                    .execute(status -> List
                            .of(fireUnchecked(removeRaProfile, certificate), fireUnchecked(renew, certificate)));
        });
        List<TriggerHistory> histories;
        try {
            histories = evaluation.get(EVALUATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            evaluationThread.shutdownNow();
        }

        // then
        assertThat(histories).isNotEmpty().allSatisfy(history -> assertThat(recordsOf(history)).isEmpty());
        assertThat(certificateRepository.findById(certificate.getUuid()).orElseThrow().getRaProfileUuid()).isNull();
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewStartedAt()).isNull();
    }

    @Test
    void clearsTheRenewalTimeAndCountersButKeepsInFlightWork_whenTheWindowChanges() {
        // given
        Certificate certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
        UUID inFlightSuccessor = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        row.setRenewAttempt(2);
        row.setRenewNotBefore(now.plus(Duration.ofHours(6)));
        row.setRenewSuccessorUuid(inFlightSuccessor);
        row.setRenewStartedAt(now);
        renewalInfoRepository.save(row);
        var laterWindow = new Window(now.plus(Duration.ofDays(2)), now.plus(Duration.ofDays(5)));

        // when
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Forced(laterWindow, null));

        // then
        CertificateRenewalInfo stored = seeder.renewalRow(certificate.getUuid());
        assertThat(stored.getRenewAt()).isNull();
        assertThat(stored.getRenewAttempt()).isZero();
        assertThat(stored.getRenewNotBefore()).isNull();
        assertThat(stored.getRenewSuccessorUuid()).isEqualTo(inFlightSuccessor);
        assertThat(stored.getRenewStartedAt()).isEqualTo(now);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private TriggerHistory fire(TriggerAssociation association, Certificate certificate) throws Exception {
        TriggerHistory history = triggerService
                .createTriggerHistory(association.getTriggerUuid(), association, certificate.getUuid(), null, null,
                        Resource.CERTIFICATE);
        certificateTriggerEvaluator.performActions(association.getTrigger(), history, certificate, null);
        return history;
    }

    private TriggerHistory fireUnchecked(TriggerAssociation association, Certificate certificate) {
        try {
            return fire(association, certificate);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The records stored for the firing, including those the renewal adds after the evaluation committed. */
    private List<TriggerHistoryRecord> recordsOf(TriggerHistory history) {
        return triggerHistoryRecordRepository
                .findAll()
                .stream()
                .filter(record -> history.getUuid().equals(record.getTriggerHistoryUuid()))
                .toList();
    }

    private List<CertificateEventHistory> renewHistory(Certificate certificate) {
        return eventHistoryRepository
                .findByCertificateOrderByCreatedDesc(certificate)
                .stream()
                .filter(entry -> entry.getEvent() == CertificateEvent.RENEW)
                .toList();
    }
}
