package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.exception.MessageHandlingException;
import com.czertainly.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.Approval;
import com.czertainly.core.dao.entity.ApprovalProfile;
import com.czertainly.core.dao.entity.ApprovalProfileRelation;
import com.czertainly.core.dao.entity.ApprovalProfileVersion;
import com.czertainly.core.dao.repository.ApprovalProfileRelationRepository;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.service.ApprovalService;
import com.czertainly.core.service.SecretService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.AuthHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
    private ApprovalService approvalService;
    @Mock
    private ClientOperationService clientOperationService;
    @Mock
    private SecretService secretService;
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
        listener.setApprovalService(approvalService);
        listener.setClientOperationService(clientOperationService);
        listener.setSecretService(secretService);
        listener.setNotificationProducer(notificationProducer);
        listener.setAuthHelper(authHelper);
        listener.setMessagingProperties(messagingProperties);

        // Only the failure-path tests read this; lenient() avoids strict-stubbing complaints
        // from happy-path tests that never invoke it.
        lenient().when(messagingProperties.routingKey()).thenReturn(new MessagingProperties.RoutingKey(
                "actions", "audit-logs", "event", "notification", "scheduler", "validation",
                "time-quality.config-request", "time-quality.config", "time-quality.results"));
    }

    // ==================== No approval needed — direct action ====================

    @Test
    void processMessage_certificateIssue_noApprovalNeeded_callsIssueCertificateAction() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, userUuid, null, null, null);

        // No approval profile configured for this resource → falls through to direct action.
        when(approvalProfileRelationRepository.findByResourceUuidAndResource(any(), any()))
                .thenReturn(Optional.of(List.of()));

        listener.processMessage(msg);

        verify(authHelper).authenticateAsUser(userUuid);
        verify(clientOperationService).issueCertificateAction(resourceUuid, false);
        verifyNoInteractions(approvalService);
        verifyNoInteractions(notificationProducer);
    }

    @Test
    void processMessage_secretResource_alreadyApproved_callsSecretServiceProcessAction() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        UUID approvalUuid = UUID.randomUUID();
        // hasApproval=true short-circuits the approval-creation branch entirely.
        ActionMessage msg = newMessage(Resource.SECRET, ResourceAction.ISSUE, resourceUuid, userUuid,
                approvalUuid, ApprovalStatusEnum.APPROVED, null);

        listener.processMessage(msg);

        verify(authHelper).authenticateAsUser(userUuid);
        verify(secretService).processSecretAction(msg, true, true);
        verifyNoInteractions(clientOperationService);
        verifyNoInteractions(approvalService);
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
    void processMessage_certificateAction_approvalProfileExists_createsApprovalAndCallsApprovalCreated() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, userUuid, null, null, null);

        stubApprovalProfileRelation();
        Approval createdApproval = new Approval();
        createdApproval.setUuid(UUID.randomUUID());
        when(approvalService.createApproval(any(), any(), any(), any(), any(), any())).thenReturn(createdApproval);

        listener.processMessage(msg);

        verify(approvalService).createApproval(any(), eq(Resource.CERTIFICATE), eq(ResourceAction.ISSUE),
                eq(resourceUuid), eq(userUuid), any());
        verify(clientOperationService).approvalCreatedAction(resourceUuid);
        // The "create approval" branch returns early — direct action must NOT run.
        verify(authHelper, never()).authenticateAsUser(any());
        verify(clientOperationService, never()).issueCertificateAction(any(), anyBoolean());
    }

    @Test
    void processMessage_secretAction_approvalProfileExists_callsSecretApprovalCreated() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.SECRET, ResourceAction.ISSUE, resourceUuid, userUuid, null, null, null);

        stubApprovalProfileRelation();
        Approval createdApproval = new Approval();
        createdApproval.setUuid(UUID.randomUUID());
        when(approvalService.createApproval(any(), any(), any(), any(), any(), any())).thenReturn(createdApproval);

        listener.processMessage(msg);

        verify(secretService).approvalCreatedAction(resourceUuid);
        verifyNoInteractions(authHelper);
    }

    @Test
    void processMessage_approvalCreationFails_producesErrorNotificationAndThrowsMessageHandlingException() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, userUuid, null, null, null);

        stubApprovalProfileRelation();
        when(approvalService.createApproval(any(), any(), any(), any(), any(), any()))
                .thenThrow(new RuntimeException("approval creation exploded"));

        assertThatThrownBy(() -> listener.processMessage(msg))
                .isInstanceOf(MessageHandlingException.class)
                .hasMessageContaining("approval creation failed");

        verify(notificationProducer).produceInternalNotificationMessage(eq(Resource.CERTIFICATE), eq(resourceUuid),
                any(), any(), any());
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
    void processMessage_certificateRevoke_rejected_doesNotCallAnyOperation() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.REVOKE, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.REJECTED, null);

        listener.processMessage(msg);

        // REVOKE is not in the rejected-action allowlist (ISSUE/RENEW/REKEY only) — it logs and returns.
        verify(clientOperationService, never()).issueCertificateRejectedAction(any());
        verify(clientOperationService, never()).revokeCertificateAction(any(), any(), anyBoolean());
    }

    // ==================== Authentication failure ====================

    @Test
    void processMessage_authenticateAsUserFails_producesErrorNotificationAndThrowsMessageHandlingException() throws Exception {
        UUID resourceUuid = UUID.randomUUID();
        UUID userUuid = UUID.randomUUID();
        ActionMessage msg = newMessage(Resource.CERTIFICATE, ResourceAction.ISSUE, resourceUuid, userUuid,
                UUID.randomUUID(), ApprovalStatusEnum.APPROVED, null);

        doThrow(new RuntimeException("auth blew up"))
                .when(authHelper).authenticateAsUser(userUuid);

        assertThatThrownBy(() -> listener.processMessage(msg))
                .isInstanceOf(MessageHandlingException.class)
                .hasMessageContaining("Unable to process action");

        verify(notificationProducer).produceInternalNotificationMessage(eq(Resource.CERTIFICATE), eq(resourceUuid),
                any(), any(), any());
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
