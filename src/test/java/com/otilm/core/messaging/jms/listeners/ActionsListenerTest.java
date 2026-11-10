package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.MessageHandlingException;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.ApprovalProfileRelation;
import com.otilm.core.dao.entity.ApprovalProfileVersion;
import com.otilm.core.dao.repository.ApprovalProfileRelationRepository;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.ApprovalInternalService;
import com.otilm.core.service.SecretInternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthHelper;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ActionsListenerTest {

    @Mock
    private ApprovalProfileRelationRepository approvalProfileRelationRepository;
    @Mock
    private ApprovalInternalService approvalInternalService;
    @Mock
    private ClientOperationInternalService clientOperationService;
    @Mock
    private SecretInternalService secretService;
    @Mock
    private NotificationProducer notificationProducer;
    @Mock
    private AuthHelper authHelper;
    @Mock
    private MessagingProperties messagingProperties;

    private ActionsListener listener;

    @BeforeEach
    void setUp() {
        listener = new ActionsListener();
        listener.setApprovalProfileRelationRepository(approvalProfileRelationRepository);
        listener.setApprovalService(approvalInternalService);
        listener.setClientOperationService(clientOperationService);
        listener.setSecretService(secretService);
        listener.setNotificationProducer(notificationProducer);
        listener.setAuthHelper(authHelper);
        listener.setMessagingProperties(messagingProperties);
        listener.setMapper(ObjectMapperFactory.wire());

        // Only the failure-path tests read this; lenient() avoids strict-stubbing complaints
        // from happy-path tests that never invoke it.
        lenient()
                .when(messagingProperties.routingKey())
                .thenReturn(new MessagingProperties.RoutingKey("actions", "audit-logs", "event", "notification",
                        "scheduler", "validation", "time-quality.config-request", "time-quality.config",
                        "time-quality.results", "provider.status-poll", "provider.discovery-work"));
    }

    // ==================== No approval needed — direct action ====================

    @Test
    void issuesTheCertificateAsItsRequester_whenNoApprovalIsNeeded() throws Exception {
        // given — no approval profile for the resource
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, userUuid, null, null,
                null);
        when(approvalProfileRelationRepository.findByResourceUuidAndResource(any(), any()))
                .thenReturn(Optional.of(List.of()));

        // when
        listener.processMessage(msg);

        // then
        verify(authHelper).authenticateAsUser(userUuid);
        verify(clientOperationService).issueCertificateAction(resourceUuid, null, false);
        verifyNoInteractions(approvalInternalService);
        verifyNoInteractions(notificationProducer);
    }

    @Test
    void issuesTheRequestTheIssueWasQueuedFor_whenNoApprovalIsNeeded() throws Exception {
        // given
        UUID certificateUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, certificateUuid, UUID.randomUUID(),
                null, null, null);
        UUID queuedFor = UUID.randomUUID();
        msg.setCertificateRequestUuid(queuedFor);
        when(approvalProfileRelationRepository.findByResourceUuidAndResource(any(), any()))
                .thenReturn(Optional.of(List.of()));

        // when
        listener.processMessage(msg);

        // then
        verify(clientOperationService).hasNothingToIssue(certificateUuid, queuedFor);
        verify(clientOperationService).issueCertificateAction(certificateUuid, queuedFor, false);
    }

    @Test
    void dropsTheIssue_whenTheCertificateHoldsNothingToIssue() throws Exception {
        // given — an issue that reached the broker although queuing it failed and its registration completion was
        // undone
        UUID registrationUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, registrationUuid, UUID.randomUUID(),
                null, null, null);
        UUID queuedFor = UUID.randomUUID();
        msg.setCertificateRequestUuid(queuedFor);
        when(clientOperationService.hasNothingToIssue(registrationUuid, queuedFor)).thenReturn(true);

        // when
        listener.processMessage(msg);

        // then
        verify(clientOperationService, never()).issueCertificateAction(any(), any(), anyBoolean());
        verifyNoInteractions(approvalProfileRelationRepository, approvalInternalService, notificationProducer);
    }

    @Test
    void processMessage_secretResource_alreadyApproved_callsSecretServiceProcessAction() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        UUID approvalUuid = UUID.randomUUID();
        // hasApproval=true short-circuits the approval-creation branch entirely.
        ActionMessage msg = newMessage(Resource.SECRET, ResourceAction.ISSUE, resourceUuid, userUuid, approvalUuid,
                ApprovalStatusEnum.APPROVED, null);

        listener.processMessage(msg);

        verify(authHelper).authenticateAsUser(userUuid);
        verify(secretService).processSecretAction(msg, true, true);
        verifyNoInteractions(clientOperationService);
        verifyNoInteractions(approvalInternalService);
    }

    @Test
    void processMessage_unsupportedResource_doesNothingAndDoesNotThrow() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.RA_PROFILE, ResourceAction.UPDATE, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.APPROVED, null);

        listener.processMessage(msg);

        verify(authHelper).authenticateAsUser(userUuid);
        verifyNoInteractions(clientOperationService);
        verifyNoInteractions(secretService);
        verifyNoInteractions(notificationProducer);
    }

    // ==================== Approval profile present — creates approval ====================

    @Test
    void requestsTheApprovalThroughTheClientOperationService_whenACertificateActionNeedsOne() throws Exception {
        // given
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, UUID.randomUUID(), UUID.randomUUID(),
                null, null, null);
        stubApprovalProfileRelation();

        // when
        listener.processMessage(msg);

        // then — the action itself waits for the approval
        verify(clientOperationService).requestApproval(any(), eq(msg));
        verifyNoInteractions(approvalInternalService);
        verify(authHelper, never()).authenticateAsUser(any());
        verify(clientOperationService, never()).issueCertificateAction(any(), any(), anyBoolean());
    }

    @Test
    void processMessage_secretAction_approvalProfileExists_callsSecretApprovalCreated() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.SECRET, ResourceAction.ISSUE, resourceUuid, userUuid, null, null, null);

        stubApprovalProfileRelation();
        Approval createdApproval = new Approval();
        createdApproval.setUuid(UUID.randomUUID());
        when(approvalInternalService.createApproval(any(), any(), any(), any(), any(), any()))
                .thenReturn(createdApproval);

        listener.processMessage(msg);

        verify(secretService).approvalCreatedAction(resourceUuid);
        verifyNoInteractions(authHelper);
    }

    @Test
    void rejectsTheMessageWithANotification_whenRequestingTheApprovalFails() throws Exception {
        // given
        UUID resourceUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, UUID.randomUUID(),
                null, null, null);
        stubApprovalProfileRelation();
        doThrow(new RuntimeException("approval creation exploded"))
                .when(clientOperationService)
                .requestApproval(any(), any());

        // when
        ThrowingCallable process = () -> listener.processMessage(msg);

        // then
        assertThatThrownBy(process)
                .isInstanceOf(MessageHandlingException.class)
                .hasMessageContaining("approval creation failed");
        verify(notificationProducer)
                .produceInternalNotificationMessage(eq(Resource.CERTIFICATE), eq(resourceUuid), any(), any(), any());
    }

    // ==================== Certificate action variants (with approval) ====================

    @Test
    void processMessage_certificateRekey_approved_deserializesDtoAndCallsRekey() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        // Empty Map deserializes to a default-constructed ClientCertificateRekeyRequestDto.
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.REKEY, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.APPROVED, Map.of());

        listener.processMessage(msg);

        verify(authHelper).authenticateAsUser(userUuid);
        verify(clientOperationService).rekeyCertificateAction(eq(resourceUuid), any(), eq(true));
        verify(clientOperationService, never()).issueCertificateRejectedAction(any());
    }

    @Test
    void processMessage_certificateRekey_rejected_callsIssueCertificateRejectedAction() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.REKEY, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.REJECTED, null);

        listener.processMessage(msg);

        verify(clientOperationService).issueCertificateRejectedAction(resourceUuid);
        // Rejected REKEY must NOT attempt the actual rekey path or its DTO deserialization.
        verify(clientOperationService, never()).rekeyCertificateAction(any(), any(), anyBoolean());
    }

    @Test
    void processMessage_certificateRevoke_rejected_callsRevokeCertificateRejectedAction() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.REVOKE, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.REJECTED, null);

        listener.processMessage(msg);

        verify(clientOperationService).revokeCertificateRejectedAction(resourceUuid);
        // A rejected REVOKE must not run the issue-rejection path nor the actual revoke.
        verify(clientOperationService, never()).issueCertificateRejectedAction(any());
        verify(clientOperationService, never()).revokeCertificateAction(any(), any(), anyBoolean());
    }

    // ==================== Authentication failure ====================

    @Test
    void processMessage_authenticateAsUserFails_producesErrorNotificationAndThrowsMessageHandlingException()
            throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.APPROVED, null);

        doThrow(new RuntimeException("auth blew up")).when(authHelper).authenticateAsUser(userUuid);

        assertThatThrownBy(() -> listener.processMessage(msg))
                .isInstanceOf(MessageHandlingException.class)
                .hasMessageContaining("Unable to process action");

        verify(notificationProducer)
                .produceInternalNotificationMessage(eq(Resource.CERTIFICATE), eq(resourceUuid), any(), any(), any());
        verifyNoInteractions(clientOperationService);
    }

    // ==================== Helpers ====================

    private ActionMessage newMessage(Resource resource, ResourceAction action, UUID resourceUuid, UUID userUuid,
            UUID approvalUuid, ApprovalStatusEnum approvalStatus, Object data) {
        ActionMessage msg = new ActionMessage();
        msg.setResource(resource);
        msg.setResourceAction(action);
        msg.setResourceUuid(resourceUuid);
        msg.setUserUuid(userUuid);
        msg.setApprovalUuid(approvalUuid);
        msg.setApprovalStatus(approvalStatus);
        msg.setData(data);
        msg.setApprovalProfileResource(resource);
        msg.setApprovalProfileResourceUuid(resourceUuid);
        return msg;
    }

    private void stubApprovalProfileRelation() {
        ApprovalProfileVersion version = new ApprovalProfileVersion();
        ApprovalProfile profile = mock(ApprovalProfile.class);
        when(profile.getTheLatestApprovalProfileVersion()).thenReturn(version);
        ApprovalProfileRelation relation = new ApprovalProfileRelation();
        relation.setApprovalProfile(profile);
        when(approvalProfileRelationRepository.findByResourceUuidAndResource(any(), any()))
                .thenReturn(Optional.of(List.of(relation)));
    }

}
