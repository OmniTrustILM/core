package com.otilm.core.events.handlers;

import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.messaging.model.NotificationRecipient;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Component(ResourceEvent.Codes.COMMENT_CREATED)
public class CommentCreatedEventHandler extends CommentEventsHandler {

    @Autowired
    protected CommentCreatedEventHandler(CommentRepository repository, TriggerEvaluator<Comment> triggerEvaluator) {
        super(repository, triggerEvaluator);
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<Comment> eventContext) {
        Comment comment = eventContext.getResourceObjects().getFirst();
        UUID actingUser = eventContext.getUserUuid();

        // A new root is its own thread: its only participant is the acting author, which leaves the owner
        UUID rootUuid = comment.getParentUuid() == null ? comment.getUuid() : comment.getParentUuid();
        List<NotificationRecipient> recipients = threadRecipientsExcept(comment, rootUuid, actingUser);
        publishFollowUpNotification(eventContext, comment, recipients);
    }
}
