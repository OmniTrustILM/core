package com.otilm.core.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.EventException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.core.dao.entity.UniquelyIdentifiedObject;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.util.AuthHelper;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
public abstract class EventHandler<T extends UniquelyIdentifiedObject> implements IEventHandler {

    private static final Logger logger = LoggerFactory.getLogger(EventHandler.class);

    protected AuthHelper authHelper;
    protected ObjectMapper objectMapper;
    protected EventProducer eventProducer;
    protected ApplicationEventPublisher applicationEventPublisher;
    protected EventHistoryRepository eventHistoryRepository;

    protected final TriggerEvaluator<T> triggerEvaluator;
    protected final SecurityFilterRepository<T, UUID> repository;

    private TriggerAssociationRepository triggerAssociationRepository;

    @Autowired
    public void setAuthHelper(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    @Autowired
    public void setEventHistoryRepository(EventHistoryRepository eventHistoryRepository) {
        this.eventHistoryRepository = eventHistoryRepository;
    }

    @Autowired
    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Autowired
    public void setTriggerAssociationRepository(TriggerAssociationRepository triggerAssociationRepository) {
        this.triggerAssociationRepository = triggerAssociationRepository;
    }

    protected EventHandler(SecurityFilterRepository<T, UUID> repository, TriggerEvaluator<T> triggerEvaluator) {
        this.repository = repository;
        this.triggerEvaluator = triggerEvaluator;
    }

    protected EventContext<T> prepareContext(EventMessage eventMessage) throws EventException {
        T resourceObject = repository
                .findByUuid(SecuredUUID.fromUUID(eventMessage.getObjectUuid()))
                .orElseThrow(() -> new EventException(eventMessage.getEvent(), "%s with UUID %s not found"
                        .formatted(eventMessage.getResource().getLabel(), eventMessage.getObjectUuid())));

        EventContext<T> context = new EventContext<>(eventMessage, triggerEvaluator, resourceObject,
                getEventData(resourceObject, eventMessage.getData()));
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones

        return context;
    }

    protected abstract Object getEventData(T object, Object eventMessageData);

    protected List<EventContextTriggers> getOverridingTriggers(EventContext<T> eventContext, T object)
            throws EventException {
        return List.of();
    }

    public void handleEvent(EventMessage eventMessage) throws EventException {
        logger.debug("Going to handle event '{}'", eventMessage.getEvent().getLabel());
        EventContext<T> eventContext;
        eventContext = prepareContext(eventMessage);
        processAllTriggers(eventContext);
        sendFollowUpEventsNotifications(eventContext);
        logger.debug("Event '{}' successfully handled", eventMessage.getEvent().getLabel());
    }

    protected EventHistory createEventHistory(ResourceEvent event, Resource overrideResource, UUID overrideObjectUuid) {
        EventHistory eventHistory = new EventHistory();
        eventHistory.setEvent(event);
        eventHistory.setResource(overrideResource);
        eventHistory.setResourceUuid(overrideObjectUuid);
        eventHistory.setStatus(EventStatus.IN_PROGRESS);
        eventHistory.setStartedAt(OffsetDateTime.now());
        return eventHistoryRepository.save(eventHistory);
    }

    protected void sendFollowUpEventsNotifications(EventContext<T> eventContext) {
        // No follow-up events or internal notifications are sent by default
    }

    protected EventContextTriggers fetchEventTriggers(EventContext<T> context, Resource resource, UUID objectUuid)
            throws EventException {
        List<TriggerAssociation> triggerAssociations = triggerAssociationRepository
                .findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(context.getEvent(), resource, objectUuid);

        EventContextTriggers eventContextTriggers;
        if (resource == null && objectUuid == null) {
            eventContextTriggers = context.getPlatformTriggers();
        } else {
            if (resource == null || objectUuid == null) {
                throw new EventException(context.getEvent(), "Error in fetching triggers for event '%s'. %s is null"
                        .formatted(context.getEvent().getLabel(), resource == null ? "Resource" : "Object UUID"));
            }
            String triggersKey = "%s.%s".formatted(resource.toString(), objectUuid.toString());
            eventContextTriggers = context
                    .getOverridingResourceTriggers()
                    .computeIfAbsent(triggersKey, key -> new EventContextTriggers(resource, objectUuid));
        }

        for (TriggerAssociation triggerAssociation : triggerAssociations) {
            if (triggerAssociation.getTrigger().isIgnoreTrigger()) {
                eventContextTriggers.getIgnoreTriggers().add(triggerAssociation);
            } else {
                eventContextTriggers.getTriggers().add(triggerAssociation);
            }
        }

        return eventContextTriggers;
    }

    protected void processAllTriggers(EventContext<T> context) throws EventException {
        for (int i = 0; i < context.getResourceObjects().size(); i++) {
            T resourceObject = context.getResourceObjects().get(i);
            Object eventData = context.getResourceObjectsEventData().get(i);

            // load overriding triggers
            List<EventContextTriggers> overridingTriggers = getOverridingTriggers(context, resourceObject);
            for (EventContextTriggers triggers : overridingTriggers) {
                processTriggers(context, triggers, resourceObject, eventData);
            }

            // at the end process platform triggers
            processTriggers(context, context.getPlatformTriggers(), resourceObject, eventData);
        }
        logger.debug("Triggers of event '{}' successfully handled", context.getEvent().getLabel());
    }

    protected void processTriggers(EventContext<T> context, EventContextTriggers eventTriggers, T resourceObject,
            Object eventData) {
        if (eventTriggers.getTriggers().isEmpty() && eventTriggers.getIgnoreTriggers().isEmpty()) {
            return;
        }
        logger
                .debug("Going to process {} triggers from {} {} on {} object(s) registered for event '{}'",
                        eventTriggers.getIgnoreTriggers().size() + eventTriggers.getTriggers().size(),
                        eventTriggers.getResource() == null
                                ? Resource.SETTINGS.getLabel()
                                : eventTriggers.getResource().getLabel(),
                        eventTriggers.getObjectUuid(), context.getResourceObjects().size(),
                        context.getEvent().getLabel());

        EventHistory eventHistory = createEventHistory(context.getEvent(), eventTriggers.getResource(),
                eventTriggers.getObjectUuid());
        try {
            // First, check the ignore triggers
            boolean isIgnored = evaluateIgnoreTriggers(context, eventTriggers, resourceObject, eventData, eventHistory);
            // If some trigger ignored this object, processing is stopped
            if (isIgnored) {
                saveEventHistory(eventHistory, EventStatus.FINISHED);
                return;
            }

            // Evaluate the rest of the triggers in given order
            evaluateTriggers(context, eventTriggers, resourceObject, eventData, eventHistory);
        } catch (Exception e) {
            logger
                    .error("Unable to process triggers for {} object {}. Message: {}", context.getResource().getLabel(),
                            resourceObject.getUuid(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        saveEventHistory(eventHistory, EventStatus.FINISHED);
    }

    protected void saveEventHistory(EventHistory eventHistory, EventStatus finished) {
        eventHistory.setStatus(finished);
        eventHistory.setFinishedAt(OffsetDateTime.now());
        eventHistoryRepository.save(eventHistory);
    }

    protected void evaluateTriggers(EventContext<T> context, EventContextTriggers eventTriggers, T resourceObject,
            Object eventData, EventHistory eventHistory) {
        evaluateTriggers(context, eventTriggers, resourceObject, eventData, eventHistory, null);
    }

    protected void evaluateTriggers(EventContext<T> context, EventContextTriggers eventTriggers, T resourceObject,
            Object eventData, EventHistory eventHistory, List<RequestAttribute> pendingCustomAttributes) {
        withActingUserRestored(context, () -> {
            evaluateTriggerAssociations(context, eventTriggers, resourceObject, eventData, eventHistory,
                    pendingCustomAttributes);
            return null;
        });
    }

    private void evaluateTriggerAssociations(EventContext<T> context, EventContextTriggers eventTriggers,
            T resourceObject, Object eventData, EventHistory eventHistory,
            List<RequestAttribute> pendingCustomAttributes) {
        for (TriggerAssociation triggerAssociation : eventTriggers.getTriggers()) {
            handleUser(context, triggerAssociation.getTriggeredBy());
            Trigger trigger = triggerAssociation.getTrigger();
            try {
                context
                        .getTriggerEvaluator()
                        .evaluateTrigger(trigger, triggerAssociation, resourceObject, null, eventData, eventHistory,
                                pendingCustomAttributes);
                logger
                        .debug("Trigger '{}' on {} object {} processed successfully", trigger.getName(),
                                context.getResource().getLabel(), resourceObject.getUuid());
            } catch (Exception e) {
                logger
                        .error("Unable to process trigger '{}' on {} object {}. Message: {}", trigger.getName(),
                                context.getResource().getLabel(), resourceObject.getUuid(), e.getMessage());
            }
        }
    }

    protected boolean evaluateIgnoreTriggers(EventContext<T> context, EventContextTriggers eventTriggers,
            T resourceObject, Object eventData, EventHistory eventHistory) {
        return evaluateIgnoreTriggers(context, eventTriggers, resourceObject, eventData, eventHistory, null);
    }

    protected boolean evaluateIgnoreTriggers(EventContext<T> context, EventContextTriggers eventTriggers,
            T resourceObject, Object eventData, EventHistory eventHistory,
            List<RequestAttribute> pendingCustomAttributes) {
        return withActingUserRestored(context, () -> evaluateIgnoreTriggerAssociations(context, eventTriggers,
                resourceObject, eventData, eventHistory, pendingCustomAttributes));
    }

    private boolean evaluateIgnoreTriggerAssociations(EventContext<T> context, EventContextTriggers eventTriggers,
            T resourceObject, Object eventData, EventHistory eventHistory,
            List<RequestAttribute> pendingCustomAttributes) {
        // First, check the ignore triggers
        boolean isIgnored = false;
        for (TriggerAssociation triggerAssociation : eventTriggers.getIgnoreTriggers()) {
            handleUser(context, triggerAssociation.getTriggeredBy());
            Trigger trigger = triggerAssociation.getTrigger();
            try {
                TriggerHistory triggerHistory = context
                        .getTriggerEvaluator()
                        .evaluateTrigger(trigger, triggerAssociation, resourceObject, null, eventData, eventHistory,
                                pendingCustomAttributes);
                if (triggerHistory.isActionsPerformed()) {
                    isIgnored = true;
                }
                logger
                        .debug("Ignore trigger '{}' on {} object {} processed successfully", trigger.getName(),
                                context.getResource().getLabel(), resourceObject.getUuid());
            } catch (Exception e) {
                logger
                        .error("Unable to process ignore trigger '{}' on {} object {}. Message: {}", trigger.getName(),
                                context.getResource().getLabel(), resourceObject.getUuid(), e.getMessage());
            }
        }
        return isIgnored;
    }

    /**
     * Confines {@link #handleUser} impersonation to the trigger loop: trigger actions run as the association's owner,
     * but the audited writes afterwards (Certificate, CertificateEventHistory) belong to the acting user, and JPA
     * auditing stamps whoever is left in the context. Runs against a detached context because
     * {@code authenticateAsUser} mutates the held one in place. Mirrors {@link AuthHelper#runAsSystem}.
     */
    private <R> R withActingUserRestored(EventContext<T> context, Supplier<R> triggerEvaluation) {
        SecurityContext actingUserContext = SecurityContextHolder.getContext();
        boolean actingUserWasAuthenticated = actingUserContext.getAuthentication() != null;
        UUID actingUserUuid = context.getCurrentUserUuid();
        Map<String, String> actingUserActor = LoggingHelper.snapshotActorInfo();
        try {
            SecurityContext detached = SecurityContextHolder.createEmptyContext();
            detached.setAuthentication(actingUserContext.getAuthentication());
            SecurityContextHolder.setContext(detached);
            // Stops the acting user's actor name mixing with the trigger creator's uuid; restored in finally.
            LoggingHelper.clearActorInfo();

            return triggerEvaluation.get();
        } finally {
            if (actingUserWasAuthenticated) {
                SecurityContextHolder.setContext(actingUserContext);
            } else {
                SecurityContextHolder.clearContext();
            }
            LoggingHelper.restoreActorInfo(actingUserActor);
            context.setCurrentUserUuid(actingUserUuid);
        }
    }

    /**
     * A trigger owner that cannot be impersonated is deliberately not degraded here, unlike the per-message failure in
     * {@code EventListener}: that costs only attribution, whereas a trigger evaluated without its owner's identity
     * would run its actions under other permissions. The exception escapes, marking the event FAILED.
     */
    protected void handleUser(EventContext<T> context, UUID triggeredBy) {
        // Read from the installed principal, never from EventContext.currentUserUuid: that memo is seeded from the
        // message and can name a user the thread does not hold, which would skip a needed impersonation.
        UUID installedUserUuid = AuthHelper.getActingUserUuidOrNull();
        if (Objects.equals(installedUserUuid, triggeredBy)) {
            // No switch needed, but the actor MDC still has to name the identity in effect: the loop clears it on
            // entry, so without this the first trigger owned by the acting user would be audited with no actor at all.
            if (triggeredBy != null) {
                LoggingHelper.putActorInfoWhenNull(ActorType.USER, triggeredBy.toString(), null);
            }
            return;
        }

        try {
            logger.debug("Changing user from {} to {}", installedUserUuid, triggeredBy);
            // Drop the previous owner's attribution before installing the next: authenticateAsUser only overwrites the
            // actor uuid, and an ownerless trigger writes no actor at all, so a stale one would otherwise survive.
            LoggingHelper.clearActorInfo();
            if (triggeredBy == null) {
                SecurityContextHolder.clearContext();
            } else {
                authHelper.authenticateAsUser(triggeredBy);
                requireImpersonated(triggeredBy);
            }

            context.setCurrentUserUuid(triggeredBy);
        } catch (ValidationException e) {
            // anonymous user
            SecurityContextHolder.clearContext();
            LoggingHelper.clearActorInfo();
            context.setCurrentUserUuid(null);
        }
    }

    /**
     * Only an unreachable auth service makes {@code authenticateAsUser} throw. A deleted or disabled owner instead has
     * the auth service answer "not authenticated", which the client turns into an anonymous principal - so the call
     * returns normally and the trigger would otherwise evaluate under an identity that is neither its owner nor absent.
     */
    private void requireImpersonated(UUID triggeredBy) {
        if (!triggeredBy.equals(AuthHelper.getActingUserUuidOrNull())) {
            // Leave nothing installed for the caller to run under, independently of the loop's restore.
            SecurityContextHolder.clearContext();
            LoggingHelper.clearActorInfo();
            throw new PlatformAuthenticationException(
                    "User %s that associated the trigger could not be authenticated".formatted(triggeredBy));
        }
    }
}
