package com.czertainly.core.events.handlers;

import com.czertainly.api.exception.EventException;
import com.czertainly.api.model.common.events.data.ScheduledJobFinishedEventData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.dao.entity.ScheduledJob;
import com.czertainly.core.dao.repository.ScheduledJobsRepository;
import com.czertainly.core.evaluator.TriggerEvaluator;
import com.czertainly.core.events.EventContext;
import com.czertainly.core.events.EventContextTriggers;
import com.czertainly.core.events.EventHandler;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.model.ScheduledTaskResult;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
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
