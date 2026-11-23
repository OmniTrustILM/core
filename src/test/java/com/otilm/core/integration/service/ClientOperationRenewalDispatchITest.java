package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Renewal and rekey of an issued certificate through the service: whom the new certificate, the successor, is
 * attributed to, the caller's step before the action is queued, and what becomes of a successor whose action is never
 * queued. The mocked {@link ActionProducer} stands in for the broker, so no action runs.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class ClientOperationRenewalDispatchITest extends BaseSpringBootTest {

    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String EST_PROFILE_NAME = "devices-profile";
    private static final String PROFILE_GROUP_NAME = "device-operators";
    private static final UUID PROFILE_OWNER_UUID = UUID.fromString("0b9f7d2e-5c41-4e8a-9a63-2f1d8c7b6e54");
    private static final String PROFILE_OWNER_NAME = "device-owner";
    private static final String ISSUER_DN = "CN=Devices Issuing CA";
    private static final String SUBJECT_DN = "CN=device-1,O=Devices";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private ActionProducer actionProducer;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociationRepository;

    @Autowired
    private CertificateRelationRepository relationRepository;

    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;

    @Autowired
    private GroupRepository groupRepository;

    private WireMockServer authService;
    private WireMockServer connector;
    private RaProfile raProfile;
    private EstProfile estProfile;
    private Group profileGroup;
    private KeyPair sourceKeys;
    private X509Certificate sourceCertificate;

    @BeforeEach
    void startServersAndSeedRoute() throws Exception {
        authService = AuthServiceWireMockStubs.startImpersonating(PROFILE_OWNER_UUID, PROFILE_OWNER_NAME);
        connector = LoopbackWireMock.start();
        V3ConnectorStubs.stubAttributesAndValidate(connector);
        raProfile = routes.seedRaProfileOnV3Authority(connector, RA_PROFILE_NAME);
        profileGroup = saveGroup(PROFILE_GROUP_NAME);
        estProfile = routes
                .seedEstProfileAssociatingCertificates(EST_PROFILE_NAME, raProfile, PROFILE_OWNER_UUID,
                        profileGroup.getUuid());
        CertificateGeneratorHelper.CertificateChainInfo sourceChain = CertificateGeneratorHelper
                .generateCertificateWithIssuer(KeyAlgorithm.RSA, ISSUER_DN, SUBJECT_DN, null);
        sourceKeys = sourceChain.getEndEntityCertificateKeyPair();
        sourceCertificate = sourceChain.getEndEntityCertificate();
    }

    @AfterEach
    void stopServers() {
        authService.stop();
        connector.stop();
    }

    // ── Attribution ───────────────────────────────────────────────────────────

    @Nested
    class Attribution {

        @Test
        void attributesSuccessorToEst_whenRenewedThroughEst() throws Exception {
            // given
            Certificate source = routes.seedIssuedCertificate(sourceCertificate, raProfile);
            var throughEst = CertificateProtocolInfo.est(estProfile.getUuid());

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .renewCertificate(readAuthorityUuid(), readRaProfileUuid(), source.getUuid().toString(),
                            buildRenewalRequest(), throughEst, null);

            // then
            UUID successorUuid = UUID.fromString(response.getUuid());
            assertThat(findAttribution(successorUuid)).hasValueSatisfying(attribution -> {
                assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
                assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
            });
            assertThat(readOwner(successorUuid)).isEqualTo(PROFILE_OWNER_UUID);
        }

        @Test
        void attributesSuccessorToEst_whenRekeyedThroughEst() throws Exception {
            // given
            Certificate source = routes.seedIssuedCertificate(sourceCertificate, raProfile);
            var throughEst = CertificateProtocolInfo.est(estProfile.getUuid());

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .rekeyCertificate(readAuthorityUuid(), readRaProfileUuid(), source.getUuid().toString(),
                            buildRekeyRequest(), throughEst, null);

            // then
            UUID successorUuid = UUID.fromString(response.getUuid());
            assertThat(findAttribution(successorUuid)).hasValueSatisfying(attribution -> {
                assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
                assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
            });
            assertThat(readOwner(successorUuid)).isEqualTo(PROFILE_OWNER_UUID);
        }

        @Test
        void keepsSourceAttribution_whenRenewedWithoutProtocol() throws Exception {
            // given
            Certificate attributedSource = routes.seedIssuedCertificate(sourceCertificate, raProfile, estProfile);

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .renewCertificate(readAuthorityUuid(), readRaProfileUuid(), attributedSource.getUuid().toString(),
                            buildRenewalRequest());

            // then
            Certificate successor = findWithAssociations(UUID.fromString(response.getUuid()));
            assertThat(findAttribution(successor.getUuid()))
                    .get()
                    .extracting(CertificateProtocolAssociation::getProtocol,
                            CertificateProtocolAssociation::getProtocolProfileUuid,
                            CertificateProtocolAssociation::getAdditionalProtocolUuid)
                    .containsExactly(CertificateProtocol.EST, estProfile.getUuid(), null);
            assertThat(successor.getOwner().getOwnerUuid()).isNotEqualTo(PROFILE_OWNER_UUID);
            assertThat(successor.getGroups()).extracting(Group::getUuid).doesNotContain(profileGroup.getUuid());
        }

        @Test
        void keepsSourceAttribution_whenRekeyedWithoutProtocol() throws Exception {
            // given
            Certificate attributedSource = routes.seedIssuedCertificate(sourceCertificate, raProfile, estProfile);

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .rekeyCertificate(readAuthorityUuid(), readRaProfileUuid(), attributedSource.getUuid().toString(),
                            buildRekeyRequest());

            // then
            Certificate successor = findWithAssociations(UUID.fromString(response.getUuid()));
            assertThat(findAttribution(successor.getUuid()))
                    .get()
                    .extracting(CertificateProtocolAssociation::getProtocol,
                            CertificateProtocolAssociation::getProtocolProfileUuid,
                            CertificateProtocolAssociation::getAdditionalProtocolUuid)
                    .containsExactly(CertificateProtocol.EST, estProfile.getUuid(), null);
            assertThat(successor.getOwner().getOwnerUuid()).isNotEqualTo(PROFILE_OWNER_UUID);
            assertThat(successor.getGroups()).extracting(Group::getUuid).doesNotContain(profileGroup.getUuid());
        }

        @Test
        void keepsAcmeProfileWithoutAccount_whenRenewedWithoutProtocol() throws Exception {
            // given
            var acmeProfileUuid = UUID.randomUUID();
            var orderingAccountUuid = UUID.randomUUID();
            Certificate acmeSource = routes
                    .seedIssuedCertificate(sourceCertificate, raProfile,
                            CertificateProtocolInfo.Acme(acmeProfileUuid, orderingAccountUuid));

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .renewCertificate(readAuthorityUuid(), readRaProfileUuid(), acmeSource.getUuid().toString(),
                            buildRenewalRequest());

            // then
            assertThat(findAttribution(UUID.fromString(response.getUuid())))
                    .get()
                    .extracting(CertificateProtocolAssociation::getProtocol,
                            CertificateProtocolAssociation::getProtocolProfileUuid,
                            CertificateProtocolAssociation::getAdditionalProtocolUuid)
                    .containsExactly(CertificateProtocol.ACME, acmeProfileUuid, null);
        }

        @Test
        void leavesSuccessorUnattributed_whenSourceHasNoProtocol() throws Exception {
            // given
            Certificate unattributedSource = routes.seedIssuedCertificate(sourceCertificate, raProfile);

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .renewCertificate(readAuthorityUuid(), readRaProfileUuid(), unattributedSource.getUuid().toString(),
                            buildRenewalRequest());

            // then
            assertThat(findAttribution(UUID.fromString(response.getUuid()))).isEmpty();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** A rekey: the CSR names the source's subject with a new key. */
        private static ClientCertificateRekeyRequestDto buildRekeyRequest() throws Exception {
            KeyPair newKeys = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
            return ClientCertificateRekeyRequestDto.builder().request(signRequest(newKeys)).build();
        }

        private Optional<CertificateProtocolAssociation> findAttribution(UUID certificateUuid) {
            return protocolAssociationRepository.findByCertificateUuid(certificateUuid);
        }

        private Certificate findWithAssociations(UUID certificateUuid) {
            return certificateRepository.findWithAssociationsByUuid(certificateUuid).orElseThrow();
        }

        private UUID readOwner(UUID certificateUuid) {
            return findWithAssociations(certificateUuid).getOwner().getOwnerUuid();
        }
    }

    // ── Queuing ───────────────────────────────────────────────────────────────

    @Nested
    class Queuing {

        private Certificate source;

        @BeforeEach
        void seedSource() {
            source = routes.seedIssuedCertificate(sourceCertificate, raProfile);
        }

        @Test
        void passesSuccessorToHookFirst_whenRenewalIsPublished() throws Exception {
            // given
            Consumer<UUID> beforeDispatch = mock();

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .renewCertificate(readAuthorityUuid(), readRaProfileUuid(), source.getUuid().toString(),
                            buildRenewalRequest(), CertificateProtocolInfo.est(estProfile.getUuid()), beforeDispatch);

            // then
            UUID successorUuid = UUID.fromString(response.getUuid());
            InOrder dispatch = inOrder(beforeDispatch, actionProducer);
            dispatch.verify(beforeDispatch).accept(successorUuid);
            dispatch
                    .verify(actionProducer)
                    .produceMessage(argThat(published -> successorUuid.equals(published.getResourceUuid())));
        }

        @Test
        void failsSuccessorWithoutPublishing_whenHookThrows() throws Exception {
            // given
            List<UUID> handedOver = new ArrayList<>();
            Consumer<UUID> failingStep = certificateUuid -> {
                handedOver.add(certificateUuid);
                throw new IllegalStateException("linking the request failed");
            };
            SecuredParentUUID authorityUuid = readAuthorityUuid();
            SecuredUUID raProfileUuid = readRaProfileUuid();
            String sourceUuid = source.getUuid().toString();
            ClientCertificateRenewRequestDto request = buildRenewalRequest();
            var throughEst = CertificateProtocolInfo.est(estProfile.getUuid());

            // when
            ThrowingCallable renew = () -> clientOperationService
                    .renewCertificate(authorityUuid, raProfileUuid, sourceUuid, request, throughEst, failingStep);

            // then
            assertThatThrownBy(renew)
                    .isInstanceOf(CertificateOperationException.class)
                    .hasMessageContaining("Failed to prepare certificate");
            UUID successorUuid = handedOver.getFirst();
            assertThat(readState(successorUuid)).isEqualTo(CertificateState.FAILED);
            assertThat(findPendingRelation(successorUuid)).isEmpty();
            verify(actionProducer, never()).produceMessage(any());
        }

        @Test
        void failsSuccessor_whenPublishingFails() throws Exception {
            // given
            var brokerDown = new IllegalStateException("broker down");
            doThrow(brokerDown).when(actionProducer).produceMessage(any());
            SecuredParentUUID authorityUuid = readAuthorityUuid();
            SecuredUUID raProfileUuid = readRaProfileUuid();
            String sourceUuid = source.getUuid().toString();
            ClientCertificateRenewRequestDto request = buildRenewalRequest();

            // when
            ThrowingCallable renew = () -> clientOperationService
                    .renewCertificate(authorityUuid, raProfileUuid, sourceUuid, request);

            // then
            assertThatThrownBy(renew).isSameAs(brokerDown);
            UUID successorUuid = findSuccessor().getUuid();
            assertThat(readState(successorUuid)).isEqualTo(CertificateState.FAILED);
            assertThat(findPendingRelation(successorUuid)).isEmpty();
            assertThat(eventHistoryRepository.findByCertificateOrderByCreatedDesc(source))
                    .anyMatch(entry -> entry.getEvent() == CertificateEvent.RENEW
                            && entry.getStatus() == CertificateEventStatus.FAILED);
        }

        @Test
        void keepsSuccessor_whenItsActionTookItBeforePublishingFailed() throws Exception {
            // given — the broker took the renewal and its action took the successor, yet the publish reported a failure
            doAnswer(invocation -> {
                ActionMessage published = invocation.getArgument(0);
                Certificate taken = certificateRepository.findByUuid(published.getResourceUuid()).orElseThrow();
                taken.setState(CertificateState.PENDING_ISSUE);
                certificateRepository.save(taken);
                throw new IllegalStateException("acknowledgement lost");
            }).when(actionProducer).produceMessage(any());

            // when
            ClientCertificateDataResponseDto response = clientOperationService
                    .renewCertificate(readAuthorityUuid(), readRaProfileUuid(), source.getUuid().toString(),
                            buildRenewalRequest());

            // then
            UUID successorUuid = UUID.fromString(response.getUuid());
            assertThat(readState(successorUuid)).isEqualTo(CertificateState.PENDING_ISSUE);
            assertThat(findPendingRelation(successorUuid)).isPresent();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private CertificateState readState(UUID certificateUuid) {
            return certificateRepository.findByUuid(certificateUuid).orElseThrow().getState();
        }

        private Optional<CertificateRelation> findPendingRelation(UUID successorUuid) {
            return relationRepository
                    .findFirstByIdSuccessorCertificateUuidAndRelationTypeOrderByCreatedAtAsc(successorUuid,
                            CertificateRelationType.PENDING);
        }

        private Certificate findSuccessor() {
            List<Certificate> others = certificateRepository
                    .findAll()
                    .stream()
                    .filter(candidate -> !candidate.getUuid().equals(source.getUuid()))
                    .toList();
            assertThat(others).hasSize(1);
            return others.getFirst();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SecuredParentUUID readAuthorityUuid() {
        return raProfile.getAuthorityInstanceReference().getSecuredParentUuid();
    }

    private SecuredUUID readRaProfileUuid() {
        return raProfile.getSecuredUuid();
    }

    /** A renewal that keeps the source's key, as its CSR is signed with it. */
    private ClientCertificateRenewRequestDto buildRenewalRequest() throws Exception {
        return ClientCertificateRenewRequestDto.builder().request(signRequest(sourceKeys)).build();
    }

    private static String signRequest(KeyPair keys) throws Exception {
        return CertificateGeneratorHelper
                .generateCsrBase64Der(keys.getPrivate(), keys.getPublic(), SUBJECT_DN, SIGNATURE_ALGORITHM);
    }

    private Group saveGroup(String name) {
        Group group = new Group();
        group.setName(name);
        return groupRepository.save(group);
    }
}
