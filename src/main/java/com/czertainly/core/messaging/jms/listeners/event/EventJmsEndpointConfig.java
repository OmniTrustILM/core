package com.czertainly.core.messaging.jms.listeners.event;

import com.czertainly.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.messaging.model.EventMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;


@Component
@Profile("!test")
public class EventJmsEndpointConfig extends AbstractJmsEndpointConfig<EventMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public EventJmsEndpointConfig(
        ObjectMapper objectMapper,
        MessageProcessor<EventMessage> listenerMessageProcessor,
        RetryTemplate jmsRetryTemplate,
        MessagingProperties messagingProperties,
        MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
            "eventListener",
            messagingProperties.consumerDestination(messagingProperties.queue().event()),
            messagingProperties.queue().event(),
            messagingProperties.routingKey().event(),
            messagingConcurrencyProperties.events(),
            EventMessage.class
        );
    }
}
