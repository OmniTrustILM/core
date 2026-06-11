package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.ScheduledJobFinishedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventHandler;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.ScheduledTaskResult;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Transactional
@Component(ResourceEvent.Codes.SCHEDULED_JOB_FINISHED)
public class ScheduledJobFinishedEventHandler extends EventHandler<ScheduledJob> {

    protected ScheduledJobFinishedEventHandler(ScheduledJobsRepository repository, TriggerEvaluator<ScheduledJob> ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Override
    protected Object getEventData(ScheduledJob scheduledJob, Object eventMessageData) {
        final ScheduledTaskResult result = objectMapper.convertValue(eventMessageData, ScheduledTaskResult.class);
        return new ScheduledJobFinishedEventData(scheduledJob.getJobName(), scheduledJob.getJobType(), result.getStatus().getLabel(), scheduledJob.getUserUuid());
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<ScheduledJob> eventContext) {
        final ScheduledJob scheduledJob = eventContext.getResourceObjects().getFirst();

        if (!scheduledJob.isSystem() && scheduledJob.getUserUuid() != null) {
            final Object eventData = eventContext.getResourceObjectsEventData().getFirst();

            NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.SCHEDULED_JOB, scheduledJob.getUuid(), null, NotificationRecipient.buildUserNotificationRecipient(scheduledJob.getUserUuid()), eventData);
            applicationEventPublisher.publishEvent(notificationMessage);
        }
    }

    public static EventMessage constructEventMessage(UUID scheduledJobUuid, ScheduledTaskResult result) {
        return new EventMessage(ResourceEvent.SCHEDULED_JOB_FINISHED, Resource.SCHEDULED_JOB, scheduledJobUuid, result);
    }
}
