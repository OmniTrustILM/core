package com.otilm.core.service.writer.discovery;

import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkLeaseTest {

    private static final Duration LEASE_DURATION = Duration.ofMinutes(2);

    @Mock
    private DiscoveryWorkWriter workWriter;

    private DiscoveryWorkLease lease;

    @BeforeEach
    void createLease() {
        lease = new DiscoveryWorkLease(workWriter, LEASE_DURATION);
    }

    @AfterEach
    void clearTransactionSynchronization() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    @Nested
    class Configuration {

        @ParameterizedTest
        @ValueSource(strings = {"PT0S", "-PT1S"})
        void refusesToStart_whenTheLeaseIsNotPositive(String notALease) {
            // given
            var leaseDuration = Duration.parse(notALease);

            // when
            ThrowingCallable createLease = () -> new DiscoveryWorkLease(workWriter, leaseDuration);

            // then
            assertThatThrownBy(createLease)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("discovery.work.lease-duration");
        }
    }

    // ── Admit ─────────────────────────────────────────────────────────────────

    @Nested
    class Admit {

        @Test
        void admitsTheTickUnderAFreshToken_whenTheRowStillHoldsTheMessagesToken() {
            // given
            var messageToken = UUID.randomUUID();
            var claimedAttempt = 3;
            var message = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.DRAIN, claimedAttempt,
                    messageToken);
            when(workWriter
                    .swapLease(eq(message.discoveryUuid()), eq(DiscoveryWorkType.DRAIN), eq(messageToken),
                            any(UUID.class), any(OffsetDateTime.class)))
                    .thenReturn(true);

            // when
            Optional<DiscoveryWorkTick> admitted = lease.admit(message);

            // then
            ArgumentCaptor<UUID> swappedTo = ArgumentCaptor.forClass(UUID.class);
            verify(workWriter)
                    .swapLease(eq(message.discoveryUuid()), eq(DiscoveryWorkType.DRAIN), eq(messageToken),
                            swappedTo.capture(), any(OffsetDateTime.class));
            assertThat(swappedTo.getValue()).isNotNull().isNotEqualTo(messageToken);
            assertThat(admitted).hasValueSatisfying(tick -> {
                assertThat(tick.token()).isEqualTo(swappedTo.getValue());
                assertThat(tick.attempt()).isEqualTo(claimedAttempt);
                assertThat(tick.resolved()).isFalse();
            });
        }

        @Test
        void refusesTheTick_whenTheRowNoLongerHoldsItsToken() {
            // given
            var replacedToken = UUID.randomUUID();
            var message = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.STATUS, 0, replacedToken);
            when(workWriter.swapLease(any(), any(), any(), any(), any())).thenReturn(false);

            // when
            Optional<DiscoveryWorkTick> admitted = lease.admit(message);

            // then
            assertThat(admitted).isEmpty();
        }

        @Test
        void admitsATokenlessTickUnderTheTokenItLeasedTheRowWith_whenTheRowIsFree() {
            // given
            var tokenless = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.STATUS, 0, null);
            when(workWriter.leaseIfFree(any(), any(), any(), any(), any())).thenReturn(true);

            // when
            Optional<DiscoveryWorkTick> admitted = lease.admit(tokenless);

            // then
            ArgumentCaptor<UUID> leasedWith = ArgumentCaptor.forClass(UUID.class);
            verify(workWriter)
                    .leaseIfFree(eq(tokenless.discoveryUuid()), eq(DiscoveryWorkType.STATUS), leasedWith.capture(),
                            any(), any());
            assertThat(leasedWith.getValue()).isNotNull();
            assertThat(admitted).hasValueSatisfying(tick -> assertThat(tick.token()).isEqualTo(leasedWith.getValue()));
        }

        @Test
        void refusesATokenlessTick_whenTheRowIsLeased() {
            // given
            var tokenless = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.DRAIN, 0, null);
            when(workWriter.leaseIfFree(any(), any(), any(), any(), any())).thenReturn(false);

            // when
            Optional<DiscoveryWorkTick> admitted = lease.admit(tokenless);

            // then
            assertThat(admitted).isEmpty();
        }
    }

    // ── Resolve ───────────────────────────────────────────────────────────────

    @Nested
    class Resolve {

        @Test
        void resolvesTheTick_whenItReschedulesOutsideATransaction() {
            // given
            DiscoveryWorkTick tick = admitTick(DiscoveryWorkType.STATUS, 1);
            var nextAttempt = 2;

            // when
            tick.reschedule(nextAttempt, OffsetDateTime.now().plusSeconds(5));

            // then
            assertThat(tick.resolved()).isTrue();
            verify(workWriter)
                    .rescheduleLeased(eq(tick.discoveryUuid()), eq(DiscoveryWorkType.STATUS), eq(tick.token()),
                            eq(nextAttempt), any(OffsetDateTime.class));
        }

        @Test
        void resolvesTheTick_whenTheTransactionItReschedulesInCommits() {
            // given
            DiscoveryWorkTick tick = admitTick(DiscoveryWorkType.STATUS, 1);
            TransactionSynchronizationManager.initSynchronization();
            tick.reschedule(0, OffsetDateTime.now().plusMinutes(5));
            assertThat(tick.resolved()).as("nothing is settled before the surrounding transaction commits").isFalse();

            // when
            TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);

            // then
            assertThat(tick.resolved()).isTrue();
        }

        @Test
        void leavesTheTickUnresolved_whenTheTransactionItReschedulesInRollsBack() {
            // given
            DiscoveryWorkTick tick = admitTick(DiscoveryWorkType.STATUS, 1);
            TransactionSynchronizationManager.initSynchronization();
            tick.reschedule(0, OffsetDateTime.now().plusMinutes(5));

            // when
            TransactionSynchronizationManager
                    .getSynchronizations()
                    .forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

            // then
            assertThat(tick.resolved()).isFalse();
        }

        @Test
        void resolvesTheTick_whenItReleasesItsLeaseOnly() {
            // given
            DiscoveryWorkTick tick = admitTick(DiscoveryWorkType.DRAIN, 4);

            // when
            tick.releaseOnly();

            // then
            assertThat(tick.resolved()).isTrue();
            verify(workWriter)
                    .releaseLease(eq(tick.discoveryUuid()), eq(DiscoveryWorkType.DRAIN), eq(tick.token()),
                            any(OffsetDateTime.class));
        }
    }

    // ── HandOver ──────────────────────────────────────────────────────────────

    @Nested
    class HandOver {

        @Test
        void handsTheRowOverUnderANewToken_whenTheTickStillHoldsIt() {
            // given
            DiscoveryWorkTick tick = admitTick(DiscoveryWorkType.DRAIN, 5);
            when(workWriter.handOverLease(any(), any(), any(), any(), any())).thenReturn(true);

            // when
            Optional<DiscoveryWorkMessage> next = tick.handOver();

            // then
            ArgumentCaptor<UUID> newToken = ArgumentCaptor.forClass(UUID.class);
            verify(workWriter)
                    .handOverLease(eq(tick.discoveryUuid()), eq(DiscoveryWorkType.DRAIN), eq(tick.token()),
                            newToken.capture(), any(OffsetDateTime.class));
            assertThat(newToken.getValue()).isNotNull().isNotEqualTo(tick.token());
            assertThat(next)
                    .contains(new DiscoveryWorkMessage(tick.discoveryUuid(), DiscoveryWorkType.DRAIN, 0,
                            newToken.getValue()));
            assertThat(tick.resolved()).isTrue();
        }

        @Test
        void handsNothingOver_whenTheTicksTokenWasReplaced() {
            // given
            DiscoveryWorkTick tick = admitTick(DiscoveryWorkType.PROCESS, 0);
            when(workWriter.handOverLease(any(), any(), any(), any(), any())).thenReturn(false);

            // when
            Optional<DiscoveryWorkMessage> next = tick.handOver();

            // then
            assertThat(next).isEmpty();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private DiscoveryWorkTick admitTick(DiscoveryWorkType workType, int attempt) {
        var message = new DiscoveryWorkMessage(UUID.randomUUID(), workType, attempt, UUID.randomUUID());
        when(workWriter.swapLease(any(), any(), any(), any(), any())).thenReturn(true);
        return lease.admit(message).orElseThrow();
    }
}
