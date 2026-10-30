package com.otilm.core.events.handlers;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.common.events.data.ApprovalEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventHandler;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.events.transaction.UpdateCertificateHistoryEvent;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.util.AuthHelper;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Component(ResourceEvent.Codes.APPROVAL_CLOSED)
public class ApprovalClosedEventHandler extends EventHandler<Approval> {

    @Autowired
    protected ApprovalClosedEventHandler(ApprovalRepository repository, TriggerEvaluator<Approval> ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Override
    protected Object getEventData(Approval approval, Object eventMessageData) {
        ApprovalProfile approvalProfile = approval.getApprovalProfileVersion().getApprovalProfile();

        return EventDataBuilder
                .getApprovalEventData(approval, approvalProfile,
                        authHelper.getUserUsername(approval.getCreatorUuid().toString()));
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<Approval> eventContext) {
        Approval approval = eventContext.getResourceObjects().getFirst();
        ApprovalEventData eventData = (ApprovalEventData) eventContext.getResourceObjectsEventData().getFirst();

        NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.APPROVAL,
                approval.getUuid(), null,
                NotificationRecipient.buildUserNotificationRecipient(approval.getCreatorUuid()), eventData);
        applicationEventPublisher.publishEvent(notificationMessage);

        // produce only for certificates for now until refactoring and uniting of event history for all resources
        if (approval.getResource() == Resource.CERTIFICATE) {
            applicationEventPublisher
                    .publishEvent(new UpdateCertificateHistoryEvent(approval.getObjectUuid(),
                            CertificateEvent.APPROVAL_CLOSE, CertificateEventStatus.SUCCESS,
                            "Approval for action %s with approval profile %s closed with status %s"
                                    .formatted(approval.getAction().getCode(), eventData.getApprovalProfileName(),
                                            eventData.getStatus().getLabel()),
                            null));
        }
    }

    /**
     * Carries the approving or rejecting user so the certificate history row names them. A close as
     * {@link ApprovalStatusEnum#EXPIRED} carries nobody: the expiry sweep runs as the scheduled job's user, who took no
     * action on the approval, so that row is left to the system user.
     */
    public static EventMessage constructEventMessage(UUID approvalUuid, ApprovalStatusEnum closingStatus) {
        UUID actingUser = closingStatus == ApprovalStatusEnum.EXPIRED ? null : AuthHelper.getActingUserUuidOrNull();
        return new EventMessage(ResourceEvent.APPROVAL_CLOSED, Resource.APPROVAL, approvalUuid, null, null, null,
                actingUser, null);
    }
}
