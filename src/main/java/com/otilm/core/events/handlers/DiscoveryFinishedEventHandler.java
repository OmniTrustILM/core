package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.DiscoveryHistory;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventHandler;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.events.transaction.ScheduledJobFinishedEvent;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.tasks.ScheduledJobInfo;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.UUID;

@Transactional
@Component(ResourceEvent.Codes.DISCOVERY_FINISHED)
public class DiscoveryFinishedEventHandler extends EventHandler<DiscoveryHistory> {

    private final DiscoveryRepository discoveryRepository;

    protected DiscoveryFinishedEventHandler(DiscoveryRepository repository, TriggerEvaluator<DiscoveryHistory> ruleEvaluator) {
        super(repository, ruleEvaluator);
        discoveryRepository = repository;
    }

    @Override
    protected EventContext<DiscoveryHistory> prepareContext(EventMessage eventMessage) throws EventException {
        DiscoveryHistory discovery = discoveryRepository.findByUuid(eventMessage.getObjectUuid()).orElseThrow(() -> new EventException(eventMessage.getEvent(), "Discovery with UUID %s not found".formatted(eventMessage.getObjectUuid())));
        DiscoveryResult discoveryResult = objectMapper.convertValue(eventMessage.getData(), DiscoveryResult.class);

        // set discovery status to completed when discovery is in preprocessing state coming from certificate discovered event
        if (discoveryResult.getDiscoveryStatus() == DiscoveryStatus.PROCESSING) {
            String message = discoveryResult.getMessage() == null ? "Discovery completed successfully." : "Discovery completed successfully. " + discoveryResult.getMessage();
            discovery.setMessage(message);
            discovery.setStatus(DiscoveryStatus.COMPLETED);
            discovery.setEndTime(new Date());
            discoveryRepository.save(discovery);
        }

        EventContext<DiscoveryHistory> context = new EventContext<>(eventMessage, triggerEvaluator, discovery, getEventData(discovery, eventMessage.getData()));
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones

        return context;
    }

    @Override
    protected Object getEventData(DiscoveryHistory discovery, Object eventMessageData) {
        return EventDataBuilder.getDiscoveryFinishedEventData(discovery);
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<DiscoveryHistory> eventContext) {
        DiscoveryHistory discovery = eventContext.getResourceObjects().getFirst();
        Object eventData = eventContext.getResourceObjectsEventData().getFirst();
        NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.DISCOVERY, discovery.getUuid(), null, NotificationRecipient.buildUserNotificationRecipient(eventContext.getUserUuid()), eventData);
        applicationEventPublisher.publishEvent(notificationMessage);

        // if discovery was scheduled, raise application event to notify that scheduled discovery has finished
        if (eventContext.getScheduledJobInfo() != null) {
            ScheduledTaskResult scheduledTaskResult = new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, discovery.getMessage(), Resource.DISCOVERY, discovery.getUuid().toString());
            applicationEventPublisher.publishEvent(new ScheduledJobFinishedEvent(eventContext.getScheduledJobInfo(), scheduledTaskResult));
        }
    }

    public static EventMessage constructEventMessage(UUID discoveryUuid, UUID userUuid, ScheduledJobInfo scheduledJobInfo, DiscoveryResult discoveryResult) {
        return new EventMessage(ResourceEvent.DISCOVERY_FINISHED, Resource.DISCOVERY, discoveryUuid, null, null, discoveryResult, userUuid, scheduledJobInfo);
    }

}
