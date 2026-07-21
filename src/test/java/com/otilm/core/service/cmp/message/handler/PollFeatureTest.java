package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import jakarta.persistence.EntityManager;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PollFeature}.
 *
 * <p>Pinned outcomes of the {@link PollResult} contract:</p>
 * <ul>
 *   <li>Cert in expected state → {@link PollResult.Reached};</li>
 *   <li>Cert still in {@code PENDING_ISSUE} / {@code PENDING_REVOKE} once the poll budget is
 *       exhausted → {@link PollResult.StillPending}. The poll must ride out {@code PENDING_*}
 *       within the budget (the issuance flow always routes through {@code PENDING_ISSUE} on
 *       the actions-listener thread, even for connectors that complete in under a second) —
 *       giving up on the first {@code PENDING_*} sample made nearly every CMP issuance answer
 *       the initial ir/cr with a poll response;</li>
 *   <li>Cert in a terminal state that is <em>not</em> the expected one (e.g. {@code FAILED}
 *       observed while waiting for {@code ISSUED}, the asynchronous-cancel race) →
 *       {@link PollResult.Diverted};</li>
 *   <li>{@link NotFoundException} from the certificate service → {@link CmpProcessingException}
 *       carrying the cause;</li>
 *   <li>Cert never leaves a transitional state within the configured budget → timeout
 *       {@link CmpProcessingException}.</li>
 * </ul>
 */
class PollFeatureTest {

    private CertificateInternalService certificateService;
    private PollFeature pollFeature;

    @BeforeEach
    void setUp() throws Exception {
        certificateService = mock(CertificateInternalService.class);
        EntityManager entityManager = mock(EntityManager.class);
        pollFeature = new PollFeature();
        pollFeature.setCertificateService(certificateService);
        // @Value / @PersistenceContext fields set via reflection so the test runs without a
        // Spring context. Budget-exhaustion tests set the timeout to 0 so they don't wait.
        setField("pollFeatureTimeout", 1);
        setField("entityManager", entityManager);
    }

    private void setField(String name, Object value) throws Exception {
        Field field = PollFeature.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(pollFeature, value);
    }

    @Test
    void returnsStillPending_whenCertStuckInPendingIssue_afterBudgetExhausted() throws Exception {
        // Cert never leaves PENDING_ISSUE (true async connector, HTTP 202); once the budget is
        // exhausted the poll reports StillPending — not a timeout exception. Budget is 0 here so
        // the test doesn't spend real wall-clock; the "rides out the budget" behaviour is covered
        // by the ride-through test below.
        setField("pollFeatureTimeout", 0);
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.PENDING_ISSUE);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED);

        assertThat(result).isInstanceOfSatisfying(PollResult.StillPending.class,
                sp -> assertThat(sp.currentState()).isEqualTo(CertificateState.PENDING_ISSUE));
    }

    @Test
    void ridesThroughPendingIssue_andReturnsReached_whenStateFlipsWithinBudget() throws Exception {
        // The actions listener parks the cert in PENDING_ISSUE for the duration of the
        // connector call — even a synchronously-completing connector transits this state.
        // The poll must keep sampling instead of giving up on the first PENDING_ISSUE read.
        // NOTE: this exercises a real sampling interval (one ~1s sleep) to prove the loop
        // actually rides out PENDING; kept deliberately rather than adding a test-only seam.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.PENDING_ISSUE);
        AtomicInteger reads = new AtomicInteger();
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenAnswer(invocation -> {
                    if (reads.incrementAndGet() >= 2) {
                        cert.setState(CertificateState.ISSUED);
                    }
                    return cert;
                });

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED);

        assertThat(result).isInstanceOfSatisfying(PollResult.Reached.class,
                r -> assertThat(r.certificate()).isSameAs(cert));
        assertThat(reads.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void returnsStillPending_whenCertStuckInPendingRevoke_afterBudgetExhausted() throws Exception {
        setField("pollFeatureTimeout", 0);   // 0 budget so the exhaustion is immediate (no real wait)
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.PENDING_REVOKE);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.REVOKED);

        assertThat(result).isInstanceOfSatisfying(PollResult.StillPending.class,
                sp -> assertThat(sp.currentState()).isEqualTo(CertificateState.PENDING_REVOKE));
    }

    @Test
    void returnsReached_whenCertAlreadyInExpectedState() throws Exception {
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.ISSUED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED);

        assertThat(result).isInstanceOfSatisfying(PollResult.Reached.class,
                r -> assertThat(r.certificate()).isSameAs(cert));
    }

    @Test
    void returnsDiverted_whenCertEndsInTerminalStateNotEqualToExpected() throws Exception {
        // Race: cert was diverted to FAILED while waiting for ISSUED — typically because an
        // operator-driven cancelPendingCertificateOperation transitioned the cert mid-poll.
        // Caller must reject the operation cleanly rather than time out with systemFailure.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.FAILED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED);

        assertThat(result).isInstanceOfSatisfying(PollResult.Diverted.class,
                d -> assertThat(d.currentState()).isEqualTo(CertificateState.FAILED));
    }

    @Test
    void returnsDiverted_whenCertEndsInRejectedButExpectedIssued() throws Exception {
        // Cert was rejected (e.g. by an approver) while the issue request was being polled —
        // a terminal state that is not ISSUED. Caller must reject cleanly.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.REJECTED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED);

        assertThat(result).isInstanceOfSatisfying(PollResult.Diverted.class,
                d -> assertThat(d.currentState()).isEqualTo(CertificateState.REJECTED));
    }

    @Test
    void ridesThroughIssued_andReturnsReached_whenRevocationLandsWithinBudget() throws Exception {
        // ISSUED is the resting state a certificate occupies before a revocation
        // transitions, so a revoke poll that samples ISSUED first must keep waiting for the
        // async ISSUED -> REVOKED transition instead of rejecting it as "diverted to ISSUED".
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.ISSUED);
        AtomicInteger reads = new AtomicInteger();
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenAnswer(invocation -> {
                    if (reads.incrementAndGet() >= 2) {
                        cert.setState(CertificateState.REVOKED);
                    }
                    return cert;
                });

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.REVOKED);

        assertThat(result).isInstanceOfSatisfying(PollResult.Reached.class,
                r -> assertThat(r.certificate()).isSameAs(cert));
        assertThat(reads.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void timesOut_whenRevokeNeverLeavesIssued_ratherThanReportingDivertedToIssued() throws Exception {
        // If the revocation never takes effect (cert stuck at ISSUED), the poll must NOT
        // report a false "diverted to ISSUED"; it rides out the budget and ends as a timeout,
        // which the revocation handler surfaces as a plain rejection.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.ISSUED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        Field timeoutField = PollFeature.class.getDeclaredField("pollFeatureTimeout");
        timeoutField.setAccessible(true);
        timeoutField.set(pollFeature, 0);

        assertThatThrownBy(() -> pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.REVOKED))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("polling timed out");
    }

    @Test
    void returnsDiverted_whenCertEndsInFailedButExpectedRevoked() throws Exception {
        // A genuine divergence on the revoke path (FAILED, not the benign ISSUED precursor)
        // is still reported as Diverted so the caller rejects cleanly.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.FAILED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.REVOKED);

        assertThat(result).isInstanceOfSatisfying(PollResult.Diverted.class,
                d -> assertThat(d.currentState()).isEqualTo(CertificateState.FAILED));
    }

    @Test
    void wrapsNotFoundException_withCmpProcessingException() throws Exception {
        UUID certUuid = UUID.randomUUID();
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenThrow(new NotFoundException(Certificate.class, certUuid));

        assertThatThrownBy(() -> pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED))
                .isInstanceOf(CmpProcessingException.class)
                .hasCauseInstanceOf(NotFoundException.class);
    }

    @Test
    void fillsInSerialNumber_whenCallerPassesNull() throws Exception {
        // The caller may not have the serial number at hand when polling kicks off (e.g.
        // during an issue request where the cert hasn't been issued yet); the loop fills it
        // in from the polled entity on the first iteration so subsequent log lines and
        // outcome messages carry the right SN.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.ISSUED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        PollResult result = pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), null /* serialNumber */, certUuid.toString(), CertificateState.ISSUED);

        assertThat(result).isInstanceOf(PollResult.Reached.class);
    }

    @Test
    void wrapsInterruptedException_withCmpProcessingException() throws Exception {
        // The poll loop sleeps between iterations. A test thread that interrupts itself
        // before calling pollCertificate causes the very first sleep to throw
        // InterruptedException; the catch wraps it in a CmpProcessingException carrying the
        // cause, and the interrupted flag is restored so callers further up the stack can
        // observe the interrupt.
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.REQUESTED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        Thread.currentThread().interrupt();
        try {
            assertThatThrownBy(() -> pollFeature.pollCertificate(
                    new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED))
                    .isInstanceOf(CmpProcessingException.class)
                    .hasCauseInstanceOf(InterruptedException.class);
            assertThat(Thread.currentThread().isInterrupted())
                    .as("interrupted flag should be restored").isTrue();
        } finally {
            // Clear the flag regardless of outcome so subsequent tests are not affected.
            Thread.interrupted();
        }
    }

    @Test
    void throwsCmpProcessingException_whenTimeoutAndStillTransitional() throws Exception {
        // Cert in REQUESTED state never reaches ISSUED; 0 budget makes the timeout immediate.
        setField("pollFeatureTimeout", 0);
        UUID certUuid = UUID.randomUUID();
        Certificate cert = certificateInState(certUuid, CertificateState.REQUESTED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(cert);

        assertThatThrownBy(() -> pollFeature.pollCertificate(
                new DEROctetString(new byte[]{1}), "01", certUuid.toString(), CertificateState.ISSUED))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("polling timed out");
    }

    private static Certificate certificateInState(UUID uuid, CertificateState state) {
        Certificate cert = new Certificate();
        cert.setUuid(uuid);
        cert.setState(state);
        cert.setSerialNumber("01");
        cert.setSubjectDn("CN=test");
        return cert;
    }
}
