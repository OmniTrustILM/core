package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import jakarta.persistence.EntityManager;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PollFeature}. That the loop holds no transaction, and that the reached certificate is read
 * fresh under open-in-view, is covered by {@code CmpPollTransactionITest}.
 */
@ExtendWith(MockitoExtension.class)
class PollFeatureTest {

    private static final DEROctetString TID = new DEROctetString(new byte[]{1});

    @Mock
    private CertificateInternalService certificateService;
    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private PlatformTransactionManager transactionManager;
    @Mock
    private EntityManager entityManager;

    private final UUID certUuid = UUID.randomUUID();
    private PollFeature pollFeature;

    @BeforeEach
    void wirePollFeatureWithNoBudget() {
        pollFeature = new PollFeature();
        pollFeature.setCertificateService(certificateService);
        pollFeature.setCertificateRepository(certificateRepository);
        pollFeature.setTransactionManager(transactionManager);
        pollFeature.setEntityManager(entityManager);
        pollFeature.setPollFeatureTimeout(0);
    }

    @Test
    void returnsTheRefreshedCertificate_whenItIsAlreadyInTheExpectedState() throws Exception {
        // given
        Certificate issued = certificateInState(CertificateState.ISSUED);
        stubStates(CertificateState.ISSUED);
        TransactionStatus loadTransaction = stubLoadOf(issued);

        // when
        PollResult result = pollFeature.pollCertificate(TID, null, certUuid.toString(), CertificateState.ISSUED);

        // then
        assertThat(result).isEqualTo(new PollResult.Reached(issued));
        verify(entityManager).refresh(issued);
        verify(transactionManager).commit(loadTransaction);
    }

    @Test
    void returnsReached_whenPendingIssueTurnsIssuedWithinTheBudget() throws Exception {
        // given
        pollFeature.setPollFeatureTimeout(1);
        Certificate issued = certificateInState(CertificateState.ISSUED);
        stubStates(CertificateState.PENDING_ISSUE, CertificateState.ISSUED);
        stubLoadOf(issued);

        // when
        PollResult result = pollFeature.pollCertificate(TID, "01", certUuid.toString(), CertificateState.ISSUED);

        // then
        assertThat(result).isEqualTo(new PollResult.Reached(issued));
    }

    @Test
    void returnsReached_whenRevocationLandsWithinTheBudget() throws Exception {
        // given
        pollFeature.setPollFeatureTimeout(1);
        Certificate revoked = certificateInState(CertificateState.REVOKED);
        stubStates(CertificateState.ISSUED, CertificateState.REVOKED);
        stubLoadOf(revoked);

        // when
        PollResult result = pollFeature.pollCertificate(TID, "01", certUuid.toString(), CertificateState.REVOKED);

        // then
        assertThat(result).isEqualTo(new PollResult.Reached(revoked));
    }

    @ParameterizedTest
    @MethodSource("asynchronousStatesAndTheirTargets")
    void returnsStillPending_whenTheBudgetEndsInAnAsynchronousState(CertificateState stuckIn,
            CertificateState expectedState) throws Exception {
        // given
        stubStates(stuckIn);

        // when
        PollResult result = pollFeature.pollCertificate(TID, "01", certUuid.toString(), expectedState);

        // then
        assertThat(result).isEqualTo(new PollResult.StillPending(stuckIn));
    }

    @Test
    void loadsNoCertificate_whileItIsPending() throws Exception {
        // given
        stubStates(CertificateState.REQUESTED);

        // when
        pollFeature.pollCertificate(TID, "01", certUuid.toString(), CertificateState.ISSUED);

        // then
        verifyNoInteractions(certificateService, entityManager, transactionManager);
    }

    @ParameterizedTest
    @MethodSource("terminalStatesOtherThanTheTarget")
    void returnsDiverted_whenTheCertificateEndsInAnotherTerminalState(CertificateState endedIn,
            CertificateState expectedState) throws Exception {
        // given
        stubStates(endedIn);

        // when
        PollResult result = pollFeature.pollCertificate(TID, "01", certUuid.toString(), expectedState);

        // then
        assertThat(result).isEqualTo(new PollResult.Diverted(endedIn));
    }

    @Test
    void throwsTimeout_whenCertificateStaysPendingApproval() {
        // given
        stubStates(CertificateState.PENDING_APPROVAL);

        // when
        ThrowingCallable poll = () -> pollFeature
                .pollCertificate(TID, "01", certUuid.toString(), CertificateState.ISSUED);

        // then
        assertThatThrownBy(poll).isInstanceOf(CmpProcessingException.class).hasMessageContaining("polling timed out");
    }

    @Test
    void throwsTimeout_whenRevocationNeverLeavesIssued() {
        // given
        stubStates(CertificateState.ISSUED);

        // when
        ThrowingCallable poll = () -> pollFeature
                .pollCertificate(TID, "01", certUuid.toString(), CertificateState.REVOKED);

        // then
        assertThatThrownBy(poll).isInstanceOf(CmpProcessingException.class).hasMessageContaining("polling timed out");
    }

    @Test
    void throwsBadDataFormat_whenTheCertificateIsGone() {
        // given
        when(certificateRepository.findStateByUuid(certUuid)).thenReturn(Optional.empty());

        // when
        ThrowingCallable poll = () -> pollFeature
                .pollCertificate(TID, "01", certUuid.toString(), CertificateState.ISSUED);

        // then
        assertThatThrownBy(poll)
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badDataFormat))
                .hasCauseInstanceOf(NotFoundException.class);
    }

    @Test
    void rollsTheLoadBack_whenTheReachedCertificateCannotBeLoaded() throws Exception {
        // given
        stubStates(CertificateState.ISSUED);
        TransactionStatus loadTransaction = new SimpleTransactionStatus();
        when(transactionManager.getTransaction(any())).thenReturn(loadTransaction);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenThrow(new NotFoundException(Certificate.class, certUuid));

        // when
        ThrowingCallable poll = () -> pollFeature
                .pollCertificate(TID, "01", certUuid.toString(), CertificateState.ISSUED);

        // then
        assertThatThrownBy(poll)
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badDataFormat));
        verify(transactionManager).rollback(loadTransaction);
    }

    @Test
    void throwsAndKeepsTheInterruptFlag_whenInterruptedWhileWaiting() {
        // given
        pollFeature.setPollFeatureTimeout(1);
        stubStates(CertificateState.REQUESTED);
        Thread.currentThread().interrupt();

        // when
        ThrowingCallable poll = () -> pollFeature
                .pollCertificate(TID, "01", certUuid.toString(), CertificateState.ISSUED);

        // then
        try {
            assertThatThrownBy(poll)
                    .isInstanceOf(CmpProcessingException.class)
                    .hasCauseInstanceOf(InterruptedException.class);
            assertThat(Thread.currentThread().isInterrupted()).as("interrupted flag restored").isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubStates(CertificateState first, CertificateState... next) {
        Optional<CertificateState>[] following = Stream.of(next).map(Optional::of).toArray(Optional[]::new);
        when(certificateRepository.findStateByUuid(certUuid)).thenReturn(Optional.of(first), following);
    }

    private TransactionStatus stubLoadOf(Certificate certificate) throws NotFoundException {
        TransactionStatus loadTransaction = new SimpleTransactionStatus();
        when(transactionManager.getTransaction(any())).thenReturn(loadTransaction);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class))).thenReturn(certificate);
        return loadTransaction;
    }

    private Certificate certificateInState(CertificateState state) {
        return aCertificate().withUuid(certUuid).withState(state).withSerialNumber("01").build();
    }

    static Stream<Arguments> asynchronousStatesAndTheirTargets() {
        return Stream
                .of(Arguments.of(CertificateState.REQUESTED, CertificateState.ISSUED),
                        Arguments.of(CertificateState.REGISTERED, CertificateState.ISSUED),
                        Arguments.of(CertificateState.PENDING_ISSUE, CertificateState.ISSUED),
                        Arguments.of(CertificateState.PENDING_REVOKE, CertificateState.REVOKED));
    }

    static Stream<Arguments> terminalStatesOtherThanTheTarget() {
        return Stream
                .of(Arguments.of(CertificateState.FAILED, CertificateState.ISSUED),
                        Arguments.of(CertificateState.REJECTED, CertificateState.ISSUED),
                        Arguments.of(CertificateState.FAILED, CertificateState.REVOKED));
    }
}
