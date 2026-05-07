package com.czertainly.core.service.scep.impl;

import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.scep.PkiStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.entity.scep.ScepTransaction;
import com.czertainly.core.dao.repository.scep.ScepTransactionRepository;
import com.czertainly.core.service.scep.message.ScepRequest;
import com.czertainly.core.service.scep.message.ScepResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ScepServiceImpl} private polling methods (the kernels of the
 * RFC 8894 §3.3 GetCertInitial / pkiPending flow). These cover the asynchronous-acceptance
 * paths added in the 202-Accepted feature: a SCEP-tracked transaction whose certificate is
 * in {@code PENDING_ISSUE} must keep the client polling instead of erroring out.
 *
 * <p>The methods under test are private; they are invoked here via {@link ReflectionTestUtils}
 * after seeding the dependent fields (mocked repository, mocked profile) — no Spring context.
 * The high-level {@code handlePost} path requires a real PKCS#7-enveloped CERT_POLL message
 * which is too heavy for a unit test; the kernels themselves are pure branching on
 * {@link CertificateState}, so the targeted reflection invocation gives the same JaCoCo
 * coverage at a fraction of the setup cost.</p>
 */
class ScepServiceImplPollUnitTest {

    private ScepServiceImpl service;
    private ScepTransactionRepository transactionRepository;
    private ScepProfile profile;

    @BeforeEach
    void setUp() {
        service = new ScepServiceImpl();
        transactionRepository = Mockito.mock(ScepTransactionRepository.class);
        profile = Mockito.mock(ScepProfile.class);
        Mockito.when(profile.getName()).thenReturn("test-scep-profile");

        service.setScepTransactionRepository(transactionRepository);
        ReflectionTestUtils.setField(service, "scepProfile", profile);
        // raProfileBased=false by default (boolean field) — buildFailedResponse will not
        // touch raProfile.getName() under that path.
    }

    // ==================== getExistingTransaction ====================

    @Test
    void getExistingTransaction_returnsPending_whenCertificateInPendingIssue() {
        // 202 Accepted from the connector keeps the certificate in PENDING_ISSUE; SCEP must
        // map that to pkiPending so the client retries instead of getting a hard failure.
        Certificate cert = certificateInState(CertificateState.PENDING_ISSUE);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionIdAndScepProfile("tx-1", profile))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "getExistingTransaction", "tx-1");

        assertThat(response).isNotNull();
        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.PENDING);
        assertThat(certificateChain(response)).isNullOrEmpty();
    }

    @Test
    void getExistingTransaction_returnsPending_whenCertificateInPendingApproval() {
        Certificate cert = certificateInState(CertificateState.PENDING_APPROVAL);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionIdAndScepProfile("tx-2", profile))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "getExistingTransaction", "tx-2");

        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.PENDING);
    }

    @Test
    void getExistingTransaction_returnsRejected_withRejectedReason() {
        Certificate cert = certificateInState(CertificateState.REJECTED);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionIdAndScepProfile("tx-3", profile))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "getExistingTransaction", "tx-3");

        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.FAILURE);
        assertThat(failInfoText(response)).contains("rejected");
    }

    @Test
    void getExistingTransaction_returnsFailed_withFailedReason() {
        Certificate cert = certificateInState(CertificateState.FAILED);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionIdAndScepProfile("tx-4", profile))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "getExistingTransaction", "tx-4");

        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.FAILURE);
        assertThat(failInfoText(response)).contains("failed");
    }

    // ==================== pollCertificate ====================

    @Test
    void pollCertificate_returnsPending_whenNoTrackedTransaction() {
        // The originating request may still be in the queue; the client should keep polling.
        ScepRequest scepRequest = mockScepRequest("tx-5");
        Mockito.when(transactionRepository.findByTransactionId("tx-5"))
                .thenReturn(Optional.empty());

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "pollCertificate", scepRequest, null);

        assertThat(response).isNotNull();
        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.PENDING);
        // prepareMessage was invoked — it copies request fields onto the response.
        assertThat((String) ReflectionTestUtils.getField(response, "transactionId")).isEqualTo("tx-5");
    }

    @Test
    void pollCertificate_returnsPending_whenCertificateInPendingIssue() {
        ScepRequest scepRequest = mockScepRequest("tx-6");
        Certificate cert = certificateInState(CertificateState.PENDING_ISSUE);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionId("tx-6"))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "pollCertificate", scepRequest, null);

        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.PENDING);
        assertThat(certificateChain(response)).isNullOrEmpty();
    }

    @Test
    void pollCertificate_returnsRejected_whenCertificateRejected() {
        ScepRequest scepRequest = mockScepRequest("tx-7");
        Certificate cert = certificateInState(CertificateState.REJECTED);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionId("tx-7"))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "pollCertificate", scepRequest, null);

        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.FAILURE);
        assertThat(failInfoText(response)).contains("rejected");
    }

    @Test
    void pollCertificate_returnsFailed_whenCertificateFailed() {
        ScepRequest scepRequest = mockScepRequest("tx-8");
        Certificate cert = certificateInState(CertificateState.FAILED);
        ScepTransaction trx = transactionWithCert(cert);
        Mockito.when(transactionRepository.findByTransactionId("tx-8"))
                .thenReturn(Optional.of(trx));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "pollCertificate", scepRequest, null);

        assertThat(pkiStatus(response)).isEqualTo(PkiStatus.FAILURE);
        assertThat(failInfoText(response)).contains("failed");
    }

    /**
     * The catch-Exception block must not propagate — the client keeps polling and the
     * response object reflects whatever was set before the failure. Forced here by making
     * the repository throw on lookup.
     */
    @Test
    void pollCertificate_swallowsAndLogsExceptions_returningPartiallyPopulatedResponse() {
        ScepRequest scepRequest = mockScepRequest("tx-9");
        Mockito.when(transactionRepository.findByTransactionId("tx-9"))
                .thenThrow(new RuntimeException("simulated repository failure"));

        ScepResponse response = (ScepResponse) ReflectionTestUtils.invokeMethod(
                service, "pollCertificate", scepRequest, null);

        // No exception escapes — caller gets a (mostly) empty response object.
        assertThat(response).isNotNull();
    }

    // ==================== helpers ====================

    private static Certificate certificateInState(CertificateState state) {
        Certificate cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(state);
        cert.setSerialNumber("01");
        cert.setSubjectDn("CN=test");
        return cert;
    }

    private static ScepTransaction transactionWithCert(Certificate cert) {
        ScepTransaction trx = new ScepTransaction();
        trx.setUuid(UUID.randomUUID());
        trx.setCertificate(cert);
        trx.setCertificateUuid(cert.getUuid());
        trx.setTransactionId("tx-test");
        return trx;
    }

    private static ScepRequest mockScepRequest(String transactionId) {
        ScepRequest req = Mockito.mock(ScepRequest.class);
        Mockito.when(req.getTransactionId()).thenReturn(transactionId);
        Mockito.when(req.getSenderNonce()).thenReturn("MTIz");
        Mockito.when(req.getDigestAlgorithmOid()).thenReturn("2.16.840.1.101.3.4.2.1");
        return req;
    }

    private static PkiStatus pkiStatus(ScepResponse response) {
        return (PkiStatus) ReflectionTestUtils.getField(response, "pkiStatus");
    }

    private static String failInfoText(ScepResponse response) {
        return (String) ReflectionTestUtils.getField(response, "failInfoText");
    }

    @SuppressWarnings("unchecked")
    private static List<?> certificateChain(ScepResponse response) {
        return (List<?>) ReflectionTestUtils.getField(response, "certificateChain");
    }
}
