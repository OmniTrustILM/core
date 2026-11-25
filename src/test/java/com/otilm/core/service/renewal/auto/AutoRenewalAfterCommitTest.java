package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.service.TriggerInternalService;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AutoRenewalAfterCommitTest {

    private static final UUID FIRING_UUID = UUID.randomUUID();
    private static final UUID EXECUTION_UUID = UUID.randomUUID();

    @Mock
    private AutoRenewalAction action;
    @Mock
    private TriggerInternalService triggerService;
    @Mock
    private PlatformTransactionManager transactionManager;
    private AutoRenewalAfterCommit afterCommit;
    private final Certificate certificate = aCertificate().build();
    private final TriggerContext firing = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), FIRING_UUID,
            EXECUTION_UUID);

    @BeforeEach
    void createAfterCommit() {
        afterCommit = new AutoRenewalAfterCommit(action, triggerService, transactionManager);
    }

    @AfterEach
    void clearThreadState() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @Test
    void performsAtOnce_whenTheCallerHasNoTransaction() throws Exception {
        // given — no transaction synchronization is active on the thread

        // when
        afterCommit.perform(certificate, firing);

        // then
        verify(action).perform(certificate, firing);
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
    }

    @Test
    void throwsTheFailureAtOnce_whenTheCallerHasNoTransaction() throws Exception {
        // given
        var refused = new RuleException("the authority refused the request");
        doThrow(refused).when(action).perform(certificate, firing);

        // when
        ThrowingCallable perform = () -> afterCommit.perform(certificate, firing);

        // then
        assertThatThrownBy(perform).isSameAs(refused);
        verifyNoInteractions(triggerService);
    }

    // ── InsideTransaction ─────────────────────────────────────────────────────

    @Nested
    class InsideTransaction {

        @BeforeEach
        void startSynchronization() {
            TransactionSynchronizationManager.initSynchronization();
        }

        @Test
        void performsNothing_whenTheCallerHasNotCommitted() throws Exception {
            // given — the caller's transaction is still open

            // when
            afterCommit.perform(certificate, firing);

            // then
            verify(action, never()).perform(any(), any());
            assertThat(TransactionSynchronizationManager.getSynchronizations()).hasSize(1);
        }

        @Test
        void performsNothing_whenTheCallerRollsBack() throws Exception {
            // given
            afterCommit.perform(certificate, firing);

            // when
            complete(TransactionSynchronization.STATUS_ROLLED_BACK);

            // then
            verify(action, never()).perform(any(), any());
            verifyNoInteractions(triggerService);
        }

        @Test
        void performsAsTheTriggerOwner_whenTheCallerRestoredAnotherUserBeforeCommitting() throws Exception {
            // given
            var owner = authenticate("trigger-owner");
            AtomicReference<Authentication> performedAs = new AtomicReference<>();
            doAnswer(invocation -> {
                performedAs.set(SecurityContextHolder.getContext().getAuthentication());
                return null;
            }).when(action).perform(certificate, firing);
            afterCommit.perform(certificate, firing);
            var actingUser = authenticate("acting-user");
            SecurityContext actingContext = SecurityContextHolder.getContext();

            // when
            commit();

            // then
            assertThat(performedAs.get()).isSameAs(owner);
            assertThat(SecurityContextHolder.getContext()).isSameAs(actingContext);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(actingUser);
        }

        @Test
        void performsWithTheOwnersActor_whenTheCallerChangedTheActorBeforeCommitting() throws Exception {
            // given
            var ownerUuid = UUID.randomUUID();
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, ownerUuid.toString(), "trigger-owner");
            AtomicReference<UUID> actorDuringAction = new AtomicReference<>();
            doAnswer(invocation -> {
                actorDuringAction.set(LoggingHelper.getActorInfo().uuid());
                return null;
            }).when(action).perform(certificate, firing);
            afterCommit.perform(certificate, firing);
            LoggingHelper.clearActorInfo();
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, UUID.randomUUID().toString(), "acting-user");

            // when
            commit();

            // then
            assertThat(actorDuringAction).hasValue(ownerUuid);
        }

        @Test
        void restoresTheCallersActor_whenTheActionHasRun() throws Exception {
            // given
            var callerUuid = UUID.randomUUID();
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, UUID.randomUUID().toString(), "trigger-owner");
            afterCommit.perform(certificate, firing);
            LoggingHelper.clearActorInfo();
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, callerUuid.toString(), "acting-user");

            // when
            commit();

            // then
            assertThat(LoggingHelper.getActorInfo().uuid()).isEqualTo(callerUuid);
        }

        @Test
        void leavesAnActorlessCallerWithoutActor_whenTheActionFails() throws Exception {
            // given
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, UUID.randomUUID().toString(), "trigger-owner");
            doThrow(new RuleException("refused")).when(action).perform(certificate, firing);
            afterCommit.perform(certificate, firing);
            LoggingHelper.clearActorInfo();

            // when
            commit();

            // then
            assertThat(LoggingHelper.hasActorInfo()).isFalse();
        }

        @Test
        void recordsTheFailureOnTheFiring_whenTheActionFails() throws Exception {
            // given
            var reason = "Automatic renewal failed: the authority refused the request";
            doThrow(new RuleException(reason)).when(action).perform(certificate, firing);
            afterCommit.perform(certificate, firing);

            // when
            commit();

            // then
            verify(triggerService).createTriggerHistoryRecord(FIRING_UUID, null, EXECUTION_UUID, reason);
            verify(triggerService).setTriggerHistoryActionsPerformedFalse(FIRING_UUID);
        }

        @Test
        void recordsNothing_whenTheFailedFiringHasNoHistory() throws Exception {
            // given
            var withoutHistory = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), null, null);
            doThrow(new RuleException("refused")).when(action).perform(certificate, withoutHistory);
            afterCommit.perform(certificate, withoutHistory);

            // when
            commit();

            // then
            verifyNoInteractions(triggerService);
        }

        @Test
        void letsTheCommitFinish_whenTheFailureCannotBeRecorded() throws Exception {
            // given
            doThrow(new RuleException("refused")).when(action).perform(certificate, firing);
            when(triggerService.createTriggerHistoryRecord(eq(FIRING_UUID), isNull(), eq(EXECUTION_UUID), any()))
                    .thenThrow(new IllegalStateException("the firing is gone"));
            afterCommit.perform(certificate, firing);

            // when
            commit();

            // then
            verify(triggerService, never()).setTriggerHistoryActionsPerformedFalse(any());
        }

        @Test
        void recordsAFixedFailureOnTheFiring_whenTheActionFailsUnexpectedly() throws Exception {
            // given
            var internalDetail = "connection refused to db-host:5432";
            doThrow(new IllegalStateException(internalDetail)).when(action).perform(certificate, firing);
            afterCommit.perform(certificate, firing);

            // when
            commit();

            // then
            verify(triggerService)
                    .createTriggerHistoryRecord(FIRING_UUID, null, EXECUTION_UUID,
                            AutoRenewalAfterCommit.UNEXPECTED_FAILURE);
            assertThat(AutoRenewalAfterCommit.UNEXPECTED_FAILURE).doesNotContain(internalDetail);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Runs what a transaction manager runs once the caller's transaction has committed. */
    private static void commit() {
        complete(TransactionSynchronization.STATUS_COMMITTED);
    }

    private static void complete(int status) {
        TransactionSynchronizationManager
                .getSynchronizations()
                .forEach(synchronization -> synchronization.afterCompletion(status));
    }

    private static Authentication authenticate(String name) {
        var authentication = new TestingAuthenticationToken(name, null);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        return authentication;
    }
}
