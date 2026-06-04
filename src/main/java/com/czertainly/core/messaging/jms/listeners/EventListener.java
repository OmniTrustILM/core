package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.exception.EventException;
import com.czertainly.core.events.IEventHandler;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.util.AuthHelper;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Component
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@AllArgsConstructor
public class EventListener implements MessageProcessor<EventMessage> {

    private static final Logger logger = LoggerFactory.getLogger(EventListener.class);

    private AuthHelper authHelper;

    private Map<String, IEventHandler> eventHandlers;

    @Override
    public void processMessage(EventMessage eventMessage) {
        if (eventMessage.getUserUuid() != null) {
            authHelper.authenticateAsUser(eventMessage.getUserUuid());
        }

        IEventHandler eventHandler = eventHandlers.get(eventMessage.getEvent().getCode());
        try {
            eventHandler.handleEvent(eventMessage);
        } catch (EventException e) {
            logger.error("Error in handling event {}: {}. Message: {}", eventMessage.getEvent().getLabel(), e.getMessage(), eventMessage);
        }
    }

}
