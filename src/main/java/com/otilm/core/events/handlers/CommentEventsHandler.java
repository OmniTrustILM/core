package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventContextTriggers;
import com.otilm.core.events.EventHandler;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ResourceObjectAssociationService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Unlike the other event handlers, comment handling carries no ambient transaction: deciding who to notify authorizes
 * every thread participant, which makes blocking OPA calls, and a database connection must not be held across them.
 * Nothing here writes -- the event-history rows the base class keeps are written through their own short transactions.
 */
@Component
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public abstract class CommentEventsHandler extends EventHandler<Comment> {

    protected final CommentRepository commentRepository;

    protected ResourceObjectAssociationService resourceObjectAssociationService;

    private AuthorizationEnforcer authorizationEnforcer;

    protected CommentEventsHandler(CommentRepository repository, TriggerEvaluator<Comment> triggerEvaluator) {
        super(repository, triggerEvaluator);
        this.commentRepository = repository;
    }

    @Autowired
    public void setResourceObjectAssociationService(ResourceObjectAssociationService resourceObjectAssociationService) {
        this.resourceObjectAssociationService = resourceObjectAssociationService;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Override
    protected Object getEventData(Comment comment, Object eventMessageData) {
        return objectMapper.convertValue(eventMessageData, CommentEventData.class);
    }

    @Override
    protected List<EventContextTriggers> getOverridingTriggers(EventContext<Comment> eventContext, Comment comment)
            throws EventException {
        List<EventContextTriggers> eventContextTriggers = new ArrayList<>();
        for (UUID groupUuid : resourceObjectAssociationService
                .getGroupUuids(comment.getResource(), comment.getObjectUuid())) {
            eventContextTriggers.add(fetchEventTriggers(eventContext, Resource.GROUP, groupUuid));
        }
        return eventContextTriggers;
    }

    /**
     * Participants are historical: somebody who commented while they could read the host object may have lost that
     * access since. Each one is therefore re-authorized against the host before being notified, so a revoked user stops
     * learning who acts on the object and what it is called.
     */
    protected List<NotificationRecipient> threadParticipantsExcept(Comment comment, UUID rootUuid, UUID actingUser) {
        SecuredUUID hostUuid = SecuredUUID.fromUUID(comment.getObjectUuid());
        return commentRepository
                .findThreadParticipantUuids(rootUuid)
                .stream()
                .filter(participant -> !participant.equals(actingUser))
                .filter(participant -> authorizationEnforcer
                        .isAuthorizedAs(participant, comment.getResource(), ResourceAction.DETAIL, hostUuid))
                .map(participant -> new NotificationRecipient(RecipientType.USER, participant))
                .toList();
    }

    // The message carries the HOST object, not the comment: owner resolution and the notification's deep link
    // both key on the message's resource and object UUID.
    protected void publishFollowUpNotification(EventContext<Comment> eventContext, Comment comment,
            List<NotificationRecipient> recipients) {
        if (recipients.isEmpty()) {
            return;
        }
        CommentEventData eventData = (CommentEventData) eventContext.getResourceObjectsEventData().getFirst();
        applicationEventPublisher
                .publishEvent(new NotificationMessage(eventContext.getEvent(), comment.getResource(),
                        comment.getObjectUuid(), null, recipients, eventData));
    }
}
