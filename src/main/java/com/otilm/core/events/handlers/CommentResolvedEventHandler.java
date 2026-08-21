package com.otilm.core.events.handlers;

import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Component(ResourceEvent.Codes.COMMENT_RESOLVED)
public class CommentResolvedEventHandler extends CommentEventsHandler {

    @Autowired
    protected CommentResolvedEventHandler(CommentRepository repository, TriggerEvaluator<Comment> triggerEvaluator) {
        super(repository, triggerEvaluator);
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<Comment> eventContext) {
        Comment comment = eventContext.getResourceObjects().getFirst();
        publishFollowUpNotification(eventContext, comment,
                threadParticipantsExcept(comment, comment.getUuid(), eventContext.getUserUuid()));
    }
}
