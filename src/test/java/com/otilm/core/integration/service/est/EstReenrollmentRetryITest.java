package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.ConcurrentCalls;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.mocks.AuthorityV2ConnectorStubs.RENEW_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.awaitility.Awaitility.await;

/**
 * Retries of {@code /simplereenroll} through the service, which only the database remembers: a request that the client
 * repeats with the certificate that it renews is answered from the certificate that the first one created, a request
 * that was refused stays refused, and while that certificate is on its way the client gets no other.
 */
class EstReenrollmentRetryITest extends AbstractEstReenrollmentITest {

    private static final UUID APPROVER_UUID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final String LATER_ISSUING_RA_PROFILE_NAME = "devices-ra-issuing-later";

    @Autowired
    private ApprovalProfileSeeder approvals;

    @Autowired
    private ApprovalRepository approvalRepository;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private WireMockServer laterIssuingConnector;

    @AfterEach
    void stopTheConnectorThatIssuesLater() {
        if (laterIssuingConnector != null) {
            laterIssuingConnector.stop();
        }
    }

    @Test
    void answersSameSuccessor_whenIdenticalRequestIsRepeated() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(request, credentials);

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewed);
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(RENEW_PATH)));
    }

    @Test
    void createsOneSuccessor_whenIdenticalRequestsArriveConcurrently() throws Exception {
        // given
        int concurrentRequests = 3;
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        // Core validates the issue attributes before it stores the successor that an identical request finds
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(AuthorityV2ConnectorStubs.ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.okJson("true").withFixedDelay(500)));
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);

        // when
        List<ResponseEntity<byte[]>> answers = ConcurrentCalls
                .callTogether(concurrentRequests, () -> reenroll(request, credentials));

        // then
        assertThat(answers).extracting(ResponseEntity::getStatusCode).containsOnly(HttpStatus.OK);
        assertThat(answers).extracting(ResponseEntity::getBody).containsOnly(answers.getFirst().getBody());
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(RENEW_PATH)));
    }

    @Test
    void answersFromTakeover_whenClaimWasTakenOverWhileOwnerSubmitted() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issueFreshCertificate(deviceKeys));
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        CountDownLatch ownerValidation = responseGate.hold();
        Future<ResponseEntity<byte[]>> owner = ConcurrentCalls.callInBackground(() -> reenroll(request, credentials));
        await()
                .atMost(10, TimeUnit.SECONDS)
                .until(() -> connector
                        .countRequestsMatching(WireMock
                                .postRequestedFor(WireMock
                                        .urlPathMatching(AuthorityV2ConnectorStubs.ISSUE_PATH + "/attributes/validate"))
                                .build())
                        .getCount() == 1);
        responseGate.awaitHeld();
        responseGate.hold().countDown();
        jdbcTemplate.update("UPDATE est_request_claim SET claimed_at = now() - INTERVAL '1 hour'");
        ResponseEntity<byte[]> takeover = reenroll(request, credentials);

        // when
        ownerValidation.countDown();
        ResponseEntity<byte[]> ownerAnswer = owner.get(30, TimeUnit.SECONDS);

        // then
        assertThat(takeover.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ownerAnswer.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ownerAnswer.getBody()).isEqualTo(takeover.getBody());
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(RENEW_PATH)));
    }

    @Test
    void answersSuccessor_whenRetriedWithTheOldCertificateAfterIssue() throws Exception {
        // given — the authority accepts the renewal and issues it after the first answer
        RaProfile issuingLater = routeThroughAnAuthorityThatIssuesLater();
        X509Certificate oldCertificate = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(oldCertificate, issuingLater, estProfile);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withTheOldCertificate = certificateCredentials(oldCertificate);
        ResponseEntity<byte[]> first = reenroll(request, withTheOldCertificate);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        issueLater(findTheOnlyCertificateBesides(seededSource), renewed);

        // when
        ResponseEntity<byte[]> retry = reenroll(request, withTheOldCertificate);

        // then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewed);
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.ISSUED);
        laterIssuingConnector.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3ConnectorStubs.RENEW_PATH)));
    }

    @Test
    void answersFromInventory_whenSuccessorWasCreatedBeforeARestart() throws Exception {
        // given — the renewal that the request created before the restart is on its way, and only the inventory knows
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        byte[] request = signRequest(deviceKeys);
        Certificate createdBeforeTheRestart = routes
                .seedSuccessor(seededSource, raProfile, Base64.getMimeDecoder().decode(request),
                        CertificateState.PENDING_ISSUE, CertificateRelationType.PENDING);

        // when
        ResponseEntity<byte[]> answer = reenroll(request, certificateCredentials(source));

        // then
        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(answer.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(findTheOnlyCertificateBesides(seededSource).getUuid()).isEqualTo(createdBeforeTheRestart.getUuid());
        connector.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(RENEW_PATH)));
    }

    @Test
    void createsSuccessor_whenRenewalReusesTheEnrolmentCsr() throws Exception {
        // given — the client certificate was issued through the EST Profile for the request that the client renews with
        byte[] enrolmentRequest = signRequest(deviceKeys);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate enrolled = enrollThroughTheEstProfile(enrolmentRequest, source);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);

        // when
        ResponseEntity<byte[]> response = reenroll(enrolmentRequest, certificateCredentials(source));

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(response)).isEqualTo(renewed);
        assertSuccessorOf(enrolled, findInInventory(renewed));
    }

    @Test
    void answersPendingWithoutSecondApproval_whenApprovalIsPending() throws Exception {
        // given
        approvals.requireApproval(raProfile, APPROVER_UUID);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        ResponseEntity<byte[]> first = reenroll(request, credentials);

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.PENDING_APPROVAL);
        assertThat(approvalRepository.count()).isOne();
    }

    @Test
    void answersIssued_whenApprovalIsGiven() throws Exception {
        // given
        approvals.requireApproval(raProfile, APPROVER_UUID);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(request, credentials);
        giveTheApproval();

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewed);
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(approvalRepository.count()).isOne();
    }

    @Test
    void answersRejectedWithoutNewApproval_whenApprovalIsRefused() throws Exception {
        // given
        approvals.requireApproval(raProfile, APPROVER_UUID);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(request, credentials);
        refuseTheApproval();

        // when
        ThrowingCallable retry = () -> reenroll(request, credentials);

        // then — the request is refused as often as the client repeats it
        assertThatThrownBy(retry).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.REQUEST_REJECTED);
            assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
        });
        assertThatThrownBy(retry)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.REQUEST_REJECTED));
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.REJECTED);
        assertThat(approvalRepository.count()).isOne();
    }

    @Test
    void createsNewSuccessor_whenEarlierSuccessorFailed() throws Exception {
        // given — the authority could not renew the certificate when the client first asked
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        AuthorityV2ConnectorStubs.on(connector).stubRenewFailure();
        Throwable firstAnswer = catchThrowable(() -> reenroll(request, credentials));
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(firstAnswer)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.ISSUANCE_FAILED));
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewed);
        assertThat(findCertificatesBesides(seededSource))
                .extracting(Certificate::getState)
                .containsExactlyInAnyOrder(CertificateState.FAILED, CertificateState.ISSUED);
    }

    @Test
    void createsNewSuccessor_whenEarlierSuccessorWasRevoked() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(request, credentials);
        revoke(findInInventory(renewed));
        X509Certificate renewedAgain = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewedAgain);

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewedAgain);
        assertThat(findCertificatesBesides(seededSource))
                .extracting(Certificate::getState)
                .containsExactlyInAnyOrder(CertificateState.REVOKED, CertificateState.ISSUED);
    }

    @Test
    void answersNewestSuccessor_whenRetriedAfterRevokedSuccessorWasReplaced() throws Exception {
        // given — the first successor was revoked and the same request created a second one
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(request, credentials);
        revoke(findInInventory(renewed));
        X509Certificate renewedAgain = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewedAgain);
        reenroll(request, credentials);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issueFreshCertificate(deviceKeys));

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewedAgain);
        assertThat(findCertificatesBesides(seededSource))
                .extracting(Certificate::getState)
                .containsExactlyInAnyOrder(CertificateState.REVOKED, CertificateState.ISSUED);
    }

    @Test
    void refusesAnotherCsr_whenSuccessorIsPending() throws Exception {
        // given — the renewal that the first request asked for waits for an approval
        approvals.requireApproval(raProfile, APPROVER_UUID);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(signRequest(deviceKeys), credentials);
        byte[] anotherRequest = signRequest(PkiFixtures.keyPair());

        // when
        ThrowingCallable reenroll = () -> reenroll(anotherRequest, credentials);

        // then
        assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.RENEWAL_PENDING);
            assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
        });
        assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.PENDING_APPROVAL);
        assertThat(approvalRepository.count()).isOne();
    }

    @Test
    void acceptsAnotherCsr_whenSuccessorWasIssued() throws Exception {
        // given — the first request rekeyed the certificate, and the client lost the new key of the certificate that it
        // was answered with
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        EstClientCredentials credentials = certificateCredentials(source);
        KeyPair lostKeys = PkiFixtures.keyPair();
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issueFreshCertificate(lostKeys));
        ResponseEntity<byte[]> first = reenroll(signRequest(lostKeys), credentials);
        KeyPair newKeys = PkiFixtures.keyPair();
        X509Certificate rekeyed = issueFreshCertificate(newKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(rekeyed);
        byte[] requestWithANewKey = signRequest(newKeys);

        // when
        ResponseEntity<byte[]> response = reenroll(requestWithANewKey, credentials);

        // then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(response)).isEqualTo(rekeyed);
        assertSuccessorOf(seededSource, findInInventory(rekeyed));
    }

    @Test
    void answersSuccessor_whenProfileNoLongerAllowsTheRenewal() throws Exception {
        // given — since the first request, the profile forbids renewing with the same key and narrows the window
        X509Certificate source = issueDueCertificate(deviceKeys);
        routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials credentials = certificateCredentials(source);
        reenroll(request, credentials);
        forbidRenewalAndNarrowTheWindow();

        // when
        ResponseEntity<byte[]> retry = reenroll(request, credentials);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewed);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Moves the route to an RA Profile whose authority accepts a renewal and issues it later, which the status poll
     * that the platform schedules learns: a v3 authority that advertises status polling, on a connector of its own, as
     * a connector serves one authority.
     */
    private RaProfile routeThroughAnAuthorityThatIssuesLater() {
        laterIssuingConnector = LoopbackWireMock.start();
        V3ConnectorStubs.stubV3RenewAsync(laterIssuingConnector);
        return routeThroughV3Authority(laterIssuingConnector, LATER_ISSUING_RA_PROFILE_NAME,
                FeatureFlag.CERTIFICATE_STATUS_POLLING);
    }

    /** The authority reports the renewal issued with the certificate, and the status poll learns it. */
    private void issueLater(Certificate successor, X509Certificate issued) throws Exception {
        String content = Base64.getEncoder().encodeToString(issued.getEncoded());
        V3ConnectorStubs.stubIssueStatusCompleted(laterIssuingConnector, content);
        delivery.pollStatus(successor.getUuid(), CertificateOperation.RENEW);
    }

    /**
     * Has the platform issue the certificate for the request through the EST Profile, as an enrolment through the
     * profile leaves it, and returns it as the inventory holds it.
     */
    private Certificate enrollThroughTheEstProfile(byte[] request, X509Certificate issued) throws Exception {
        AuthorityV2ConnectorStubs.on(connector).stubIssue(issued);
        ClientCertificateIssueRequestDto enrolment = new ClientCertificateIssueRequestDto();
        enrolment.setRequest(Base64.getEncoder().encodeToString(Base64.getMimeDecoder().decode(request)));
        enrolment.setFormat(CertificateRequestFormat.PKCS10);
        clientOperationService
                .issueCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                        raProfile.getSecuredUuid(), enrolment, CertificateProtocolInfo.est(estProfile.getUuid()));
        return findInInventory(issued);
    }

    /** The approver gives the only approval, and its answer is delivered once the decision has committed. */
    private void giveTheApproval() throws Exception {
        approvals.approveAs(APPROVER_UUID, approvalRepository.findAll().getFirst().getUuid());
        delivery.deliverApprovalAnswers();
    }

    /** As {@link #giveTheApproval()}, but the approver refuses the approval. */
    private void refuseTheApproval() throws Exception {
        approvals.refuseAs(APPROVER_UUID, approvalRepository.findAll().getFirst().getUuid());
        delivery.deliverApprovalAnswers();
    }

    private void revoke(Certificate certificate) {
        certificate.setState(CertificateState.REVOKED);
        certificateRepository.save(certificate);
    }

    /** Forbids renewing with the same key, and opens renewal only on the last day of a certificate. */
    private void forbidRenewalAndNarrowTheWindow() {
        estProfile.setAllowRenewal(false);
        estProfile.setRenewalThreshold(1);
        estProfile = estProfileRepository.save(estProfile);
    }
}
