package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.service.est.EstProtocolProperties;
import com.otilm.core.service.est.EstRoute;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstIssuanceWaitTest {

    private static final Duration GENEROUS_BOUND = Duration.ofMinutes(1);
    private static final Duration SHORT_BOUND = Duration.ofMillis(50);
    private static final Duration INTERVAL = Duration.ofMillis(100);
    private static final int GENEROUS_SECONDS = 60;
    private static final String FINGERPRINT = "0f".repeat(32);
    private static final String OTHER_FINGERPRINT = "1e".repeat(32);

    private final UUID certificateUuid = UUID.randomUUID();

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CertificateStatusPollRepository statusPollRepository;

    private EstIssuanceWait wait;

    @BeforeEach
    void createWait() {
        wait = waitFor(INTERVAL);
    }

    @AfterEach
    void clearInterruptFlag() {
        Thread.interrupted();
    }

    @Test
    void returnsAtOnce_whenApprovalIsPending() {
        // given
        stubStates(CertificateState.PENDING_APPROVAL);

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).contains(CertificateState.PENDING_APPROVAL);
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void waitsUntilIssued_whenQueued() {
        // given
        stubStates(CertificateState.REQUESTED, CertificateState.PENDING_ISSUE, CertificateState.ISSUED);

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).contains(CertificateState.ISSUED);
        verify(certificateRepository, times(3)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void returnsAtOnce_whenStatusPollIsScheduled() {
        // given
        stubStates(CertificateState.PENDING_ISSUE);
        when(statusPollRepository.existsByCertificateUuid(certificateUuid)).thenReturn(true);

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).contains(CertificateState.PENDING_ISSUE);
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void waitsThroughAScheduledStatusPollUntilIssued_whenWaitingThroughStatusPolls() {
        // given
        stubStates(CertificateState.PENDING_ISSUE, CertificateState.PENDING_ISSUE, CertificateState.ISSUED);

        // when
        Optional<CertificateState> state = wait
                .awaitSettledThroughStatusPolls(certificateUuid, FINGERPRINT, GENEROUS_BOUND);

        // then
        assertThat(state).contains(CertificateState.ISSUED);
        verify(certificateRepository, times(3)).findEstRequestedCertificateByUuid(certificateUuid);
        verifyNoInteractions(statusPollRepository);
    }

    @Test
    void givesUpAfterItsOwnTimeout_whenWaitingThroughStatusPolls() {
        // given — the issue waits for a poll that does not complete within the bound
        stubStates(CertificateState.PENDING_ISSUE);

        // when
        long start = System.nanoTime();
        Optional<CertificateState> state = wait
                .awaitSettledThroughStatusPolls(certificateUuid, FINGERPRINT, SHORT_BOUND);
        Duration waited = Duration.ofNanos(System.nanoTime() - start);

        // then
        assertThat(state).contains(CertificateState.PENDING_ISSUE);
        assertThat(waited).isBetween(SHORT_BOUND, Duration.ofSeconds(5));
    }

    @Test
    void returnsAtOnce_whenApprovalIsPendingWhileWaitingThroughStatusPolls() {
        // given
        stubStates(CertificateState.PENDING_APPROVAL);

        // when
        Optional<CertificateState> state = wait
                .awaitSettledThroughStatusPolls(certificateUuid, FINGERPRINT, GENEROUS_BOUND);

        // then
        assertThat(state).contains(CertificateState.PENDING_APPROVAL);
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void givesUp_whenTheIssueWaitTimeoutOfTheProfilePasses() {
        // given
        stubStates(CertificateState.REQUESTED);
        var oneSecond = 1;

        // when
        long start = System.nanoTime();
        Optional<CertificateState> state = wait.awaitSettled(routeWaiting(oneSecond), certificateUuid, FINGERPRINT);
        Duration waited = Duration.ofNanos(System.nanoTime() - start);

        // then
        assertThat(state).contains(CertificateState.REQUESTED);
        assertThat(waited).isBetween(Duration.ofSeconds(oneSecond), Duration.ofSeconds(5));
    }

    @Test
    void answersFromTheFirstRead_whenTheIssueWaitTimeoutOfTheProfileIsZero() {
        // given
        stubStates(CertificateState.PENDING_ISSUE, CertificateState.ISSUED);
        var noWait = routeWaiting(0);

        // when
        Optional<CertificateState> state = wait.awaitSettled(noWait, certificateUuid, FINGERPRINT);

        // then
        assertThat(state).contains(CertificateState.PENDING_ISSUE);
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(certificateUuid);
        verifyNoInteractions(statusPollRepository);
    }

    @Test
    void readsTheStateOncePerInterval_whenTheIssueOutlastsTheTimeout() {
        // given
        stubStates(CertificateState.REQUESTED);
        var sixIntervals = Duration.ofMillis(600);
        var shortestInterval = Duration.ofMillis(100);
        var frequentWait = waitFor(shortestInterval);

        // when
        Optional<CertificateState> state = frequentWait.awaitSettled(certificateUuid, FINGERPRINT, sixIntervals);

        // then — a read at the start and one after each interval, seven in all: a slow machine may thin them out, and
        // an interval shorter than the configured one would add many
        assertThat(state).contains(CertificateState.REQUESTED);
        verify(certificateRepository, atLeast(4)).findEstRequestedCertificateByUuid(certificateUuid);
        verify(certificateRepository, atMost(8)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void waits_whenRegisteredWithAnAttachedRequest() {
        // given
        when(certificateRepository.findEstRequestedCertificateByUuid(certificateUuid))
                .thenReturn(Optional.of(certificate(CertificateState.REGISTERED, FINGERPRINT)))
                .thenReturn(Optional.of(certificate(CertificateState.ISSUED, FINGERPRINT)));

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).contains(CertificateState.ISSUED);
    }

    @ParameterizedTest
    @MethodSource("requestsOtherThanTheSubmittedOne")
    void returnsNothingAtOnce_whenCertificateCarriesAnotherRequestOrNone(String requestFingerprint) {
        // given
        stubRegistered(requestFingerprint);

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).isEmpty();
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void returnsNothing_whenRequestIsTakenOffDuringTheWait() {
        // given — a refused approval returns the registration to REGISTERED without its request
        when(certificateRepository.findEstRequestedCertificateByUuid(certificateUuid))
                .thenReturn(Optional.of(certificate(CertificateState.REGISTERED, FINGERPRINT)))
                .thenReturn(Optional.of(certificate(CertificateState.REGISTERED, null)));

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).isEmpty();
    }

    @Test
    void restoresInterruptFlag_whenInterrupted() {
        // given
        stubStates(CertificateState.REQUESTED);
        Thread.currentThread().interrupt();

        // when
        Optional<CertificateState> state = wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThat(state).contains(CertificateState.REQUESTED);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
    }

    @Test
    void asksForNoPoll_whenStateIsNotPendingIssue() {
        // given
        stubStates(CertificateState.REQUESTED, CertificateState.FAILED);

        // when
        wait.awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        verify(statusPollRepository, never()).existsByCertificateUuid(certificateUuid);
    }

    @Test
    void throwsIllegalState_whenCertificateIsGone() {
        // given
        when(certificateRepository.findEstRequestedCertificateByUuid(certificateUuid)).thenReturn(Optional.empty());

        // when
        ThrowingCallable awaitSettled = () -> wait
                .awaitSettled(routeWaiting(GENEROUS_SECONDS), certificateUuid, FINGERPRINT);

        // then
        assertThatThrownBy(awaitSettled).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void returnsFirstRead_whenAwaitedReadIsDoneAtOnce() {
        // given
        AtomicInteger reads = new AtomicInteger();

        // when
        Integer read = wait.awaitRead(GENEROUS_BOUND, reads::incrementAndGet, value -> true);

        // then
        assertThat(read).isEqualTo(1);
        assertThat(reads).hasValue(1);
    }

    @Test
    void returnsDoneRead_whenAwaitedReadIsDoneAfterAFewReads() {
        // given
        AtomicInteger reads = new AtomicInteger();
        int doneAtThirdRead = 3;

        // when
        Integer read = wait.awaitRead(GENEROUS_BOUND, reads::incrementAndGet, value -> value >= doneAtThirdRead);

        // then
        assertThat(read).isEqualTo(doneAtThirdRead);
        assertThat(reads).hasValue(doneAtThirdRead);
    }

    @Test
    void returnsLastNotDoneRead_whenTheTimeoutPassesFirst() {
        // given
        AtomicInteger reads = new AtomicInteger();

        // when
        long start = System.nanoTime();
        Integer read = wait.awaitRead(SHORT_BOUND, reads::incrementAndGet, value -> false);
        Duration waited = Duration.ofNanos(System.nanoTime() - start);

        // then
        assertThat(read).isEqualTo(reads.get());
        assertThat(waited).isBetween(SHORT_BOUND, Duration.ofSeconds(5));
    }

    @Test
    void readsOnce_whenTheTimeoutIsZero() {
        // given
        AtomicInteger reads = new AtomicInteger();

        // when
        Integer read = wait.awaitRead(Duration.ZERO, reads::incrementAndGet, value -> false);

        // then
        assertThat(read).isEqualTo(1);
        assertThat(reads).hasValue(1);
    }

    @Test
    void returnsLastReadAndRestoresInterruptFlag_whenInterrupted() {
        // given
        Thread.currentThread().interrupt();
        AtomicInteger reads = new AtomicInteger();

        // when
        Integer read = wait.awaitRead(GENEROUS_BOUND, reads::incrementAndGet, value -> false);

        // then
        assertThat(read).isEqualTo(1);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
    }

    @Test
    void settlesWithinTheGivenTimeout_whenItIsShorterThanTheConfiguredOne() {
        // given
        stubStates(CertificateState.REQUESTED);

        // when
        long start = System.nanoTime();
        Optional<CertificateState> state = wait.awaitSettled(certificateUuid, FINGERPRINT, SHORT_BOUND);
        Duration waited = Duration.ofNanos(System.nanoTime() - start);

        // then
        assertThat(state).contains(CertificateState.REQUESTED);
        assertThat(waited).isBetween(SHORT_BOUND, Duration.ofSeconds(5));
    }

    @Test
    void settlesAtTheFirstRead_whenNothingIsLeftOfTheTimeout() {
        // given
        stubStates(CertificateState.REQUESTED, CertificateState.ISSUED);

        // when
        Optional<CertificateState> state = wait.awaitSettled(certificateUuid, FINGERPRINT, Duration.ZERO);

        // then
        assertThat(state).contains(CertificateState.REQUESTED);
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(certificateUuid);
    }

    @Test
    void takesTheIssueWaitTimeoutFromTheEstProfileOfTheRoute() {
        // given
        var sevenSeconds = 7;
        EstRoute route = routeWaiting(sevenSeconds);

        // when
        Duration timeout = EstIssuanceWait.issueWaitTimeout(route);

        // then
        assertThat(timeout).isEqualTo(Duration.ofSeconds(sevenSeconds));
    }

    @Test
    void carriesTheRequest_whenTheCertificateHoldsIt() {
        // given
        stubRegistered(FINGERPRINT);

        // when
        boolean carries = wait.carriesRequest(certificateUuid, FINGERPRINT);

        // then
        assertThat(carries).isTrue();
    }

    @ParameterizedTest
    @MethodSource("requestsOtherThanTheSubmittedOne")
    void doesNotCarryTheRequest_whenTheCertificateHoldsAnotherRequestOrNone(String requestFingerprint) {
        // given
        stubRegistered(requestFingerprint);

        // when
        boolean carries = wait.carriesRequest(certificateUuid, FINGERPRINT);

        // then
        assertThat(carries).isFalse();
    }

    @Test
    void doesNotCarryTheRequest_whenTheCertificateIsGone() {
        // given
        when(certificateRepository.findEstRequestedCertificateByUuid(certificateUuid)).thenReturn(Optional.empty());

        // when
        boolean carries = wait.carriesRequest(certificateUuid, FINGERPRINT);

        // then
        assertThat(carries).isFalse();
    }

    static Stream<Arguments> requestsOtherThanTheSubmittedOne() {
        return Stream.of(arguments(named("another request", OTHER_FINGERPRINT)), arguments(named("no request", null)));
    }

    private static EstRoute routeWaiting(int issueWaitTimeoutSeconds) {
        EstProfile estProfile = anEstProfile().withIssueWaitTimeout(issueWaitTimeoutSeconds).build();
        return new EstRoute(estProfile, null, false, "devices");
    }

    private EstIssuanceWait waitFor(Duration interval) {
        var properties = new EstProtocolProperties(new EstProtocolProperties.IssueWait(interval));
        return new EstIssuanceWait(certificateRepository, statusPollRepository, properties);
    }

    private void stubStates(CertificateState first, CertificateState... following) {
        var stubbing = when(certificateRepository.findEstRequestedCertificateByUuid(certificateUuid))
                .thenReturn(Optional.of(certificate(first, FINGERPRINT)));
        for (CertificateState next : following) {
            stubbing = stubbing.thenReturn(Optional.of(certificate(next, FINGERPRINT)));
        }
    }

    private void stubRegistered(String fingerprint) {
        when(certificateRepository.findEstRequestedCertificateByUuid(certificateUuid))
                .thenReturn(Optional.of(certificate(CertificateState.REGISTERED, fingerprint)));
    }

    private EstRequestedCertificate certificate(CertificateState state, String requestFingerprint) {
        return new EstRequestedCertificate() {
            @Override
            public UUID getUuid() {
                return certificateUuid;
            }

            @Override
            public CertificateState getState() {
                return state;
            }

            @Override
            public Date getNotAfter() {
                return null;
            }

            @Override
            public String getRequestFingerprint() {
                return requestFingerprint;
            }
        };
    }
}
