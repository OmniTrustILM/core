package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.entity.est.EstRequestClaim.Operation;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.dao.repository.est.EstRequestClaimRepository.ClaimLink;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.enrollment.EstRequestClaims.ClaimedRequest;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import com.otilm.core.service.writer.est.EstRequestClaimWriter;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstRequestClaimsTest {

    private static final String REQUEST_KEY = "the-request-key";
    private static final String FINGERPRINT = "0f".repeat(32);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final UUID claimUuid = UUID.randomUUID();
    private final UUID certificateUuid = UUID.randomUUID();
    private final ResponseEntity<byte[]> answered = ResponseEntity.ok(new byte[0]);
    private final ResponseEntity<byte[]> pending = ResponseEntity.accepted().build();

    @Mock
    private EstRequestClaimWriter claimWriter;

    @Mock
    private EstIssuanceWait issuanceWait;

    @Mock
    private ClaimedRequest request;

    private EstRequestClaims claims;
    private EstRoute route;

    @BeforeEach
    void createClaimsOnARoute() {
        claims = new EstRequestClaims(claimWriter, issuanceWait);
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        EstProfile estProfile = anEstProfile().withUuid(UUID.randomUUID()).build();
        route = new EstRoute(estProfile, raProfile, false, "devices");
    }

    @Test
    void answersFromTheFoundCertificateWithoutAClaim_whenOneAnswersAlready() {
        // given
        when(request.find()).thenReturn(Optional.of(certificate(CertificateState.ISSUED)));
        when(request.answer(certificateUuid, CertificateState.ISSUED)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verifyNoInteractions(claimWriter, issuanceWait);
        verify(request, never()).submit(any());
    }

    @Test
    void submitsOnceReleasesAndAnswers_whenTheClaimIsWon() {
        // given
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty());
        when(request.submit(any())).thenReturn(certificateUuid);
        when(issuanceWait.awaitSettled(certificateUuid, FINGERPRINT, TIMEOUT))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        when(request.answer(certificateUuid, CertificateState.ISSUED)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        InOrder order = inOrder(claimWriter, request, issuanceWait);
        order
                .verify(claimWriter)
                .claim(route.estProfile().getUuid(), route.raProfile().getUuid(), Operation.ENROLL, REQUEST_KEY);
        order.verify(request).submit(any());
        order.verify(claimWriter).release(claimUuid);
        order.verify(issuanceWait).awaitSettled(certificateUuid, FINGERPRINT, TIMEOUT);
        order.verify(request).answer(certificateUuid, CertificateState.ISSUED);
    }

    @Test
    void releasesAndAnswersWithoutSubmitting_whenAWinnerCommittedBetweenTheFindAndTheClaim() {
        // given
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty(), Optional.of(certificate(CertificateState.PENDING_ISSUE)));
        when(request.answer(certificateUuid, CertificateState.PENDING_ISSUE)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(claimWriter).release(claimUuid);
        verify(request, never()).submit(any());
        verifyNoInteractions(issuanceWait);
    }

    @Test
    void releasesTheClaimAndRethrows_whenTheSubmissionFails() {
        // given
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty());
        var failure = new IllegalArgumentException("refused");
        when(request.submit(any())).thenThrow(failure);

        // when
        ThrowingCallable answerOnce = this::answerOnce;

        // then
        assertThatThrownBy(answerOnce).isSameAs(failure);
        verify(claimWriter).release(claimUuid);
        verifyNoInteractions(issuanceWait);
    }

    @Test
    void throwsIllegalState_whenTheSubmittedCertificateNoLongerCarriesItsRequest() {
        // given
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty());
        when(request.submit(any())).thenReturn(certificateUuid);
        when(issuanceWait.awaitSettled(certificateUuid, FINGERPRINT, TIMEOUT)).thenReturn(Optional.empty());

        // when
        ThrowingCallable answerOnce = this::answerOnce;

        // then
        assertThatThrownBy(answerOnce).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void linksTheStoredCertificateToTheClaim_whenTheWinnerStores() {
        // given
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty());
        when(request.submit(any())).thenAnswer(invocation -> {
            Consumer<UUID> onStored = invocation.getArgument(0);
            onStored.accept(certificateUuid);
            return certificateUuid;
        });
        when(issuanceWait.awaitSettled(certificateUuid, FINGERPRINT, TIMEOUT))
                .thenReturn(Optional.of(CertificateState.ISSUED));

        // when
        answerOnce();

        // then
        verify(claimWriter).link(claimUuid, certificateUuid);
    }

    @Test
    void followsTheClaimWithoutSubmittingAgain_whenTheClaimIsLostAtTheStore() {
        // given
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty());
        when(request.submit(any())).thenThrow(new EstRequestClaimLostException(claimUuid));
        claimLinks(certificateUuid);
        when(issuanceWait.awaitSettled(eq(certificateUuid), eq(FINGERPRINT), any(Duration.class)))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        when(request.answer(certificateUuid, CertificateState.ISSUED)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(request, times(1)).submit(any());
        verify(claimWriter).release(claimUuid);
    }

    @Test
    void answersFromTheLinkedCertificateAfterTheBoundedSettle_whenTheClaimIsLost() {
        // given
        claimIsLost();
        claimLinks(certificateUuid);
        when(issuanceWait.awaitSettled(eq(certificateUuid), eq(FINGERPRINT), any(Duration.class)))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        when(request.answer(certificateUuid, CertificateState.ISSUED)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(issuanceWait)
                .awaitSettled(eq(certificateUuid), eq(FINGERPRINT),
                        argThat(left -> !left.isNegative() && left.compareTo(TIMEOUT) <= 0));
        verify(request, never()).submit(any());
        verify(claimWriter, never()).release(any());
    }

    @Test
    void answersWithTheFailedState_whenTheLinkedCertificateFailed() {
        // given
        claimIsLost();
        claimLinks(certificateUuid);
        when(issuanceWait.awaitSettled(eq(certificateUuid), eq(FINGERPRINT), any(Duration.class)))
                .thenReturn(Optional.of(CertificateState.FAILED));
        when(request.answer(certificateUuid, CertificateState.FAILED)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(request).answer(certificateUuid, CertificateState.FAILED);
    }

    @Test
    void answersFromTheFoundCertificate_whenTheClaimIsGoneAndOneAppeared() {
        // given
        claimIsLost();
        when(issuanceWait.<Optional<ClaimLink>>awaitRead(any(), any(), any())).thenReturn(Optional.empty());
        when(request.find()).thenReturn(Optional.empty(), Optional.of(certificate(CertificateState.PENDING_ISSUE)));
        when(request.answer(certificateUuid, CertificateState.PENDING_ISSUE)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(request, times(2)).find();
    }

    @Test
    void answersPending_whenTheClaimIsGoneAndNoCertificateAppeared() {
        // given
        claimIsLost();
        when(issuanceWait.<Optional<ClaimLink>>awaitRead(any(), any(), any())).thenReturn(Optional.empty());
        when(request.find()).thenReturn(Optional.empty());
        when(request.pending()).thenReturn(pending);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(pending);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        verify(request, times(2)).find();
        verify(request, never()).submit(any());
        verify(issuanceWait, never()).awaitSettled(any(), anyString(), any(Duration.class));
    }

    @Test
    void answersPending_whenTheClaimIsStillUnlinkedAtTheTimeout() {
        // given
        claimIsLost();
        claimLinks(null);
        when(request.pending()).thenReturn(pending);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(pending);
        verify(issuanceWait, never()).awaitSettled(any(), anyString(), any(Duration.class));
        verify(request, never()).submit(any());
    }

    @Test
    void throwsIllegalState_whenTheLinkedCertificateNoLongerCarriesItsRequest() {
        // given
        claimIsLost();
        claimLinks(certificateUuid);
        when(issuanceWait.awaitSettled(any(), anyString(), any(Duration.class))).thenReturn(Optional.empty());

        // when
        ThrowingCallable answerOnce = this::answerOnce;

        // then
        assertThatThrownBy(answerOnce).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void readsTheClaimLinkOfTheRoute_whenFollowingTheClaim() {
        // given
        claimIsLost();
        when(issuanceWait.<Optional<ClaimLink>>awaitRead(any(), any(), any())).thenAnswer(invocation -> {
            Supplier<Optional<ClaimLink>> read = invocation.getArgument(1);
            return read.get();
        });
        when(request.pending()).thenReturn(pending);

        // when
        answerOnce();

        // then
        verify(claimWriter)
                .findLink(route.estProfile().getUuid(), route.raProfile().getUuid(), Operation.ENROLL, REQUEST_KEY);
    }

    @Test
    void givesTheSubmittedCertificateTheIssueWaitOfTheProfile_whenTheClaimIsWon() {
        // given
        var issueWaitOfTheProfile = Duration.ofSeconds(25);
        route = routeWithIssueWaitTimeout(25);
        claimIsWon();
        when(request.find()).thenReturn(Optional.empty());
        when(request.submit(any())).thenReturn(certificateUuid);
        when(issuanceWait.awaitSettled(certificateUuid, FINGERPRINT, issueWaitOfTheProfile))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        when(request.answer(certificateUuid, CertificateState.ISSUED)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(issuanceWait).awaitSettled(certificateUuid, FINGERPRINT, issueWaitOfTheProfile);
    }

    @Test
    void followsTheClaimForTheIssueWaitOfTheProfile_whenTheClaimIsLost() {
        // given
        var issueWaitOfTheProfile = Duration.ofSeconds(25);
        route = routeWithIssueWaitTimeout(25);
        claimIsLost();
        when(issuanceWait.<Optional<ClaimLink>>awaitRead(any(), any(), any())).thenReturn(Optional.empty());
        when(request.pending()).thenReturn(pending);

        // when
        answerOnce();

        // then
        verify(issuanceWait).awaitRead(eq(issueWaitOfTheProfile), any(), any());
    }

    @Test
    void answersFromTheLinkedCertificateAtTheFirstRead_whenTheIssueWaitOfTheProfileIsZero() {
        // given
        route = routeWithIssueWaitTimeout(0);
        claimIsLost();
        claimLinks(certificateUuid);
        when(issuanceWait.awaitSettled(certificateUuid, FINGERPRINT, Duration.ZERO))
                .thenReturn(Optional.of(CertificateState.PENDING_ISSUE));
        when(request.answer(certificateUuid, CertificateState.PENDING_ISSUE)).thenReturn(answered);

        // when
        ResponseEntity<byte[]> response = answerOnce();

        // then
        assertThat(response).isSameAs(answered);
        verify(issuanceWait).awaitRead(eq(Duration.ZERO), any(), any());
        verify(issuanceWait).awaitSettled(certificateUuid, FINGERPRINT, Duration.ZERO);
    }

    @Test
    void endsTheWait_whenTheClaimIsGone() {
        // given
        Predicate<Optional<ClaimLink>> done = captureDonePredicate();

        // when
        boolean ends = done.test(Optional.empty());

        // then
        assertThat(ends).isTrue();
    }

    @Test
    void endsTheWait_whenTheClaimLinksACertificate() {
        // given
        Predicate<Optional<ClaimLink>> done = captureDonePredicate();

        // when
        boolean ends = done.test(Optional.of(link(certificateUuid)));

        // then
        assertThat(ends).isTrue();
    }

    @Test
    void continuesTheWait_whenTheClaimLinksNothingYet() {
        // given
        Predicate<Optional<ClaimLink>> done = captureDonePredicate();

        // when
        boolean ends = done.test(Optional.of(link(null)));

        // then
        assertThat(ends).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void claimIsLost() {
        when(request.find()).thenReturn(Optional.empty());
        when(claimWriter.claim(any(), any(), any(), anyString())).thenReturn(Optional.empty());
    }

    private void claimLinks(UUID linkedCertificateUuid) {
        when(issuanceWait.<Optional<ClaimLink>>awaitRead(any(), any(), any()))
                .thenReturn(Optional.of(link(linkedCertificateUuid)));
    }

    @SuppressWarnings("unchecked")
    private Predicate<Optional<ClaimLink>> captureDonePredicate() {
        claimIsLost();
        when(issuanceWait.<Optional<ClaimLink>>awaitRead(any(), any(), any())).thenReturn(Optional.empty());
        when(request.pending()).thenReturn(pending);
        answerOnce();
        ArgumentCaptor<Predicate<Optional<ClaimLink>>> done = ArgumentCaptor.forClass(Predicate.class);
        verify(issuanceWait).awaitRead(any(), any(), done.capture());
        return done.getValue();
    }

    private ClaimLink link(UUID linkedCertificateUuid) {
        return new ClaimLink() {
            @Override
            public UUID getUuid() {
                return claimUuid;
            }

            @Override
            public UUID getCertificateUuid() {
                return linkedCertificateUuid;
            }
        };
    }

    private EstRoute routeWithIssueWaitTimeout(int seconds) {
        EstProfile estProfile = anEstProfile().withUuid(UUID.randomUUID()).withIssueWaitTimeout(seconds).build();
        return new EstRoute(estProfile, route.raProfile(), false, "devices");
    }

    private ResponseEntity<byte[]> answerOnce() {
        return claims.answerOnce(route, Operation.ENROLL, REQUEST_KEY, FINGERPRINT, request);
    }

    private void claimIsWon() {
        when(claimWriter
                .claim(route.estProfile().getUuid(), route.raProfile().getUuid(), Operation.ENROLL, REQUEST_KEY))
                .thenReturn(Optional.of(claimUuid));
    }

    private EstRequestedCertificate certificate(CertificateState state) {
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
                return FINGERPRINT;
            }
        };
    }
}
