package com.czertainly.core.messaging.jms.listeners.actions;

import com.czertainly.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.messaging.model.ActionMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;


@Component
@Profile("!test")
public class ActionsJmsEndpointConfig extends AbstractJmsEndpointConfig<ActionMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public ActionsJmsEndpointConfig(
        ObjectMapper objectMapper,
        MessageProcessor<ActionMessage> listenerMessageProcessor,
        RetryTemplate jmsRetryTemplate,
        MessagingProperties messagingProperties,
        MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
            "actionsListener",
            messagingProperties.consumerDestination(messagingProperties.queue().actions()),
            messagingProperties.queue().actions(),
            messagingProperties.routingKey().actions(),
            messagingConcurrencyProperties.actions(),
            ActionMessage.class
        );
    }
}
