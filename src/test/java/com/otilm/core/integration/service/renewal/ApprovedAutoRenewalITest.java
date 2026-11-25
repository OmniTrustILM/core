package com.otilm.core.integration.service.renewal;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.LocationExternalService;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.renewal.auto.AutoRenewalAction;
import com.otilm.core.service.renewal.auto.AutoRenewalHandler;
import com.otilm.core.service.renewal.auto.IlmKeyRenewalHandler;
import com.otilm.core.service.renewal.auto.LocationRenewalHandler;
import com.otilm.core.service.renewal.auto.TriggerContext;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import com.otilm.core.util.seeders.AutoRenewalSeeder;
import jakarta.persistence.EntityManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An automatic renewal whose RA profile asks for an approval: the renewal action waits in the approval, and the answer
 * that the approver gives reaches the real {@link com.otilm.core.messaging.jms.listeners.ActionsListener} through
 * {@link QueuedMessageDelivery}, which runs the renewal with the request it was queued with. Core's request of the
 * renewal is stubbed: it stores the successor and hands its action, carrying the request the handler or the location
 * builds, to the listener.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class ApprovedAutoRenewalITest extends BaseSpringBootTest {

    private static final UUID OWNER_UUID = UUID.fromString("0f0f0f0f-0000-4000-8000-000000000001");
    private static final UUID APPROVER_UUID = UUID.fromString("0f0f0f0f-0000-4000-8000-000000000002");
    private static final String AUTHORITY_RENEW_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/renew";
    private static final String LOCATION_PATH = "/v1/entityProvider/entities/[^/]+/locations";

    @Autowired
    private AutoRenewalSeeder seeder;
    @Autowired
    private ApprovalProfileSeeder approvals;
    @Autowired
    private ApprovalRepository approvalRepository;
    @Autowired
    private QueuedMessageDelivery delivery;
    @Autowired
    private CertificateTypeHandlerRegistry typeHandlerRegistry;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRenewalLocationRepository renewalLocationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateLocationRepository certificateLocationRepository;
    @Autowired
    private CertificateEventHistoryInternalService eventHistoryService;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManager entityManager;

    private final TriggerContext trigger = new TriggerContext(UUID.randomUUID(), OWNER_UUID, null, null);
    private final WireMockServer authority = LoopbackWireMock.start();
    private final WireMockServer entityProvider = LoopbackWireMock.start();
    private final WireMockServer authService = AuthServiceWireMockStubs.startImpersonating(OWNER_UUID, "renewal-owner");
    private Certificate certificate;
    private AutoRenewalAction action;

    @BeforeEach
    void deliverQueuedActions() {
        delivery.deliverQueuedActions();
    }

    @AfterEach
    void stopServers() {
        authority.stop();
        entityProvider.stop();
        authService.stop();
    }

    // ── IlmKeyMode ────────────────────────────────────────────────────────────

    @Nested
    class IlmKeyMode {

        private final ClientOperationInternalService renewalStub = mock(ClientOperationInternalService.class);

        @BeforeEach
        void createIlmKeyAction() {
            action = createActionWith(
                    new IlmKeyRenewalHandler(renewalStub, renewalInfoRepository, entityManager, transactionManager));
        }

        @Test
        void replacesTheOldCertificateInItsLocations_whenTheApprovedRenewalIsIssuedAtOnce() throws Exception {
            // given
            requestApprovedRenewal(seeder.seedRaProfile(authority));
            stubAuthorityRenewingAtOnce();
            approvals.approveAs(APPROVER_UUID, findOnlyApprovalUuid());

            // when
            delivery.deliverApprovalAnswers();

            // then
            Certificate successor = findRenewalSuccessor();
            assertThat(successor.getState()).isEqualTo(CertificateState.ISSUED);
            assertThat(readLocationNames(successor)).containsExactlyInAnyOrder("web", "mail");
            assertThat(readLocationNames(certificate)).isEmpty();
        }

        @Test
        void replacesTheOldCertificateInItsLocations_whenTheAuthorityIssuesTheApprovedRenewalLater() throws Exception {
            // given
            requestApprovedRenewal(seeder.seedLaterIssuingRaProfile(authority));
            V3ConnectorStubs.stubAttributesAndValidate(authority);
            V3ConnectorStubs.stubV3RenewAsync(authority);
            approvals.approveAs(APPROVER_UUID, findOnlyApprovalUuid());
            delivery.deliverApprovalAnswers();
            UUID successorUuid = findRenewalSuccessor().getUuid();
            V3ConnectorStubs.stubIssueStatusCompleted(authority, loadIssuedCertificateData());

            // when
            delivery.pollStatus(successorUuid, CertificateOperation.RENEW);

            // then
            Certificate successor = findRenewalSuccessor();
            assertThat(successor.getState()).isEqualTo(CertificateState.ISSUED);
            assertThat(readLocationNames(successor)).containsExactlyInAnyOrder("web", "mail");
            assertThat(readLocationNames(certificate)).isEmpty();
        }

        @Test
        void countsOneFailedAttemptWithoutTouchingTheLocations_whenTheApprovalIsRefused() throws Exception {
            // given
            requestApprovedRenewal(seeder.seedRaProfile(authority));
            UUID successorUuid = findRenewalSuccessor().getUuid();
            approvals.refuseAs(APPROVER_UUID, findOnlyApprovalUuid());
            delivery.deliverApprovalAnswers();

            // when
            ThrowingCallable nextFiring = () -> action.perform(certificate, trigger);

            // then
            assertThatThrownBy(nextFiring).isInstanceOf(RuleException.class).hasMessageContaining("rejected");
            assertThat(certificateRepository.findById(successorUuid).orElseThrow().getState())
                    .isEqualTo(CertificateState.REJECTED);
            assertThat(seeder.renewalRow(certificate.getUuid()).getRenewAttempt()).isEqualTo(1);
            assertThat(readLocationNames(certificate)).containsExactlyInAnyOrder("web", "mail");
            authority.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(AUTHORITY_RENEW_PATH)));
            entityProvider.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PATH + "/.*")));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /**
         * Has the firing renew a due certificate with the platform's key, which two push-only locations hold, through
         * an RA profile that asks for an approval; the renewal waits in it.
         */
        private void requestApprovedRenewal(RaProfile raProfile) throws Exception {
            certificate = seeder.seedDueHeldKeyCertificate(raProfile);
            seeder.seedPushOnlyLocations(entityProvider, certificate, "web", "mail");
            stubLocationsAnswering();
            approvals.requireApproval(raProfile, APPROVER_UUID);
            when(renewalStub
                    .renewCertificate(any(SecuredParentUUID.class), any(SecuredUUID.class),
                            eq(certificate.getUuid().toString()), any(ClientCertificateRenewRequestDto.class), isNull(),
                            any()))
                    .thenAnswer(invocation -> {
                        Certificate successor = requestRenewal(invocation.getArgument(5));
                        queueRenewal(successor, invocation.getArgument(3));
                        ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
                        response.setUuid(successor.getUuid().toString());
                        return response;
                    });
            action.perform(certificate, trigger);
        }

        private Certificate findRenewalSuccessor() {
            UUID successorUuid = seeder.renewalRow(certificate.getUuid()).getRenewSuccessorUuid();
            return certificateRepository.findById(successorUuid).orElseThrow();
        }

        private void stubLocationsAnswering() {
            entityProvider
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(LOCATION_PATH + "/remove"))
                            .willReturn(WireMock.okJson("{}")));
            entityProvider
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(LOCATION_PATH + "/push"))
                            .willReturn(WireMock.okJson("{\"withKey\": false}")));
            for (String attributes : List.of("/push/attributes", "/csr/attributes")) {
                entityProvider
                        .stubFor(WireMock
                                .get(WireMock.urlPathMatching(LOCATION_PATH + attributes))
                                .willReturn(WireMock.okJson("[]")));
            }
        }
    }

    // ── LocationMode ──────────────────────────────────────────────────────────

    @Nested
    class LocationMode {

        private final LocationExternalService locationStub = mock(LocationExternalService.class);
        private Location web;

        @BeforeEach
        void createLocationAction() {
            action = createActionWith(
                    new LocationRenewalHandler(locationStub, renewalLocationRepository, certificateRepository,
                            certificateLocationRepository, eventHistoryService, entityManager, transactionManager));
        }

        @Test
        void pushesTheRenewedCertificateInPlaceOfTheOldOne_whenTheApprovedRenewalIsIssuedAtOnce() throws Exception {
            // given
            requestApprovedRenewalInWeb(seeder.seedRaProfile(authority));
            stubAuthorityRenewingAtOnce();
            approvals.approveAs(APPROVER_UUID, findOnlyApprovalUuid());

            // when
            delivery.deliverApprovalAnswers();

            // then
            Certificate successor = findRenewalSuccessor();
            assertThat(successor.getState()).isEqualTo(CertificateState.ISSUED);
            entityProvider.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PATH + "/push")));
            assertThat(readLocationNames(successor)).containsExactly("web");
            assertThat(readLocationNames(certificate)).isEmpty();
        }

        @Test
        void completesTheLocation_whenTheNextFiringFindsTheApprovedRenewalIssuedAtOnce() throws Exception {
            // given
            requestApprovedRenewalInWeb(seeder.seedRaProfile(authority));
            stubAuthorityRenewingAtOnce();
            approvals.approveAs(APPROVER_UUID, findOnlyApprovalUuid());
            delivery.deliverApprovalAnswers();

            // when
            action.perform(certificate, trigger);

            // then
            assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
        }

        @Test
        void completesTheRenewalInTheLocation_whenTheAuthorityIssuesTheApprovedRenewalLater() throws Exception {
            // given
            requestApprovedRenewalInWeb(seeder.seedLaterIssuingRaProfile(authority));
            V3ConnectorStubs.stubAttributesAndValidate(authority);
            V3ConnectorStubs.stubV3RenewAsync(authority);
            approvals.approveAs(APPROVER_UUID, findOnlyApprovalUuid());
            delivery.deliverApprovalAnswers();
            UUID successorUuid = findRenewalSuccessor().getUuid();
            V3ConnectorStubs.stubIssueStatusCompleted(authority, loadIssuedCertificateData());

            // when
            delivery.pollStatus(successorUuid, CertificateOperation.RENEW);

            // then
            Certificate successor = findRenewalSuccessor();
            assertThat(successor.getState()).isEqualTo(CertificateState.ISSUED);
            entityProvider.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PATH + "/push")));
            assertThat(readLocationNames(successor)).containsExactly("web");
            assertThat(readLocationNames(certificate)).isEmpty();
            assertThat(seeder.locationRow(certificate, web).getCompletedAt()).isNotNull();
        }

        @Test
        void countsOneFailedAttemptWithoutPushing_whenTheApprovalIsRefused() throws Exception {
            // given
            requestApprovedRenewalInWeb(seeder.seedRaProfile(authority));
            UUID successorUuid = findRenewalSuccessor().getUuid();
            approvals.refuseAs(APPROVER_UUID, findOnlyApprovalUuid());
            delivery.deliverApprovalAnswers();

            // when
            ThrowingCallable nextFiring = () -> action.perform(certificate, trigger);

            // then
            assertThatThrownBy(nextFiring).isInstanceOf(RuleException.class).hasMessageContaining("rejected");
            assertThat(certificateRepository.findById(successorUuid).orElseThrow().getState())
                    .isEqualTo(CertificateState.REJECTED);
            assertThat(seeder.locationRow(certificate, web).getAttempt()).isEqualTo(1);
            assertThat(readLocationNames(certificate)).containsExactly("web");
            authority.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(AUTHORITY_RENEW_PATH)));
            entityProvider.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(LOCATION_PATH + "/push")));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /**
         * Has the firing renew a due certificate in the key-generating location web through an RA profile that asks for
         * an approval. As the location service does, the successor is linked to the location before its renewal is
         * queued, which then waits in the approval.
         */
        private void requestApprovedRenewalInWeb(RaProfile raProfile) throws Exception {
            certificate = seeder.seedDueCertificate(raProfile);
            web = seeder.seedKeyGeneratingLocation(entityProvider, certificate, "web");
            entityProvider
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(LOCATION_PATH + "/push"))
                            .willReturn(WireMock.okJson("{\"withKey\": true}")));
            approvals.requireApproval(raProfile, APPROVER_UUID);
            when(locationStub
                    .renewCertificateInLocationForSuccessor(any(SecuredParentUUID.class),
                            argThat(location -> web.getUuid().equals(location.getValue())), eq(certificate.getUuid()),
                            any()))
                    .thenAnswer(invocation -> {
                        Certificate successor = requestRenewal(invocation.getArgument(3));
                        seeder.seedLocationEntry(web, successor);
                        ClientCertificateRenewRequestDto inLocation = ClientCertificateRenewRequestDto
                                .builder()
                                .build();
                        inLocation.setReplaceInLocations(false);
                        queueRenewal(successor, inLocation);
                        return successor.getUuid();
                    });
            action.perform(certificate, trigger);
        }

        private Certificate findRenewalSuccessor() {
            UUID successorUuid = seeder.locationRow(certificate, web).getSuccessorUuid();
            return certificateRepository.findById(successorUuid).orElseThrow();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private AutoRenewalAction createActionWith(AutoRenewalHandler handler) {
        return new AutoRenewalAction(renewalInfoRepository, certificateRepository, eventHistoryService, entityManager,
                transactionManager, typeHandlerRegistry, List.of(handler));
    }

    /** Requests the renewal as Core does: the successor commits, then the caller sees it before it is queued. */
    private Certificate requestRenewal(Consumer<UUID> beforeDispatch) {
        TransactionTemplate own = new TransactionTemplate(transactionManager);
        own.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        Certificate successor = own.execute(status -> seeder.seedRequestedSuccessor(certificate));
        beforeDispatch.accept(successor.getUuid());
        return successor;
    }

    /** Queues the renewal action of the successor as Core does, on behalf of the trigger's owner. */
    private void queueRenewal(Certificate successor, ClientCertificateRenewRequestDto request) {
        ActionMessage message = new ActionMessage();
        message.setApprovalProfileResource(Resource.RA_PROFILE);
        message.setApprovalProfileResourceUuid(certificate.getRaProfile().getUuid());
        message.setUserUuid(OWNER_UUID);
        message.setResource(Resource.CERTIFICATE);
        message.setResourceAction(ResourceAction.RENEW);
        message.setResourceUuid(successor.getUuid());
        message.setData(request);
        delivery.deliver(message);
    }

    private UUID findOnlyApprovalUuid() {
        List<Approval> stored = approvalRepository.findAll();
        assertThat(stored).hasSize(1);
        return stored.getFirst().getUuid();
    }

    private void stubAuthorityRenewingAtOnce() throws Exception {
        authority
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(AUTHORITY_RENEW_PATH))
                        .willReturn(
                                WireMock.okJson("{ \"certificateData\": \"" + loadIssuedCertificateData() + "\" }")));
    }

    private String loadIssuedCertificateData() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream stream = getClass().getClassLoader().getResourceAsStream("client1.p12")) {
            keyStore.load(stream, "123456".toCharArray());
        }
        return Base64.getEncoder().encodeToString(keyStore.getCertificate("1").getEncoded());
    }

    private List<String> readLocationNames(Certificate owner) {
        return new TransactionTemplate(transactionManager)
                .execute(status -> certificateLocationRepository
                        .findByCertificateUuid(owner.getUuid())
                        .stream()
                        .map(entry -> entry.getLocation().getName())
                        .toList());
    }
}
