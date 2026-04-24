package com.czertainly.core.messaging.jms.listeners.notification;

import com.czertainly.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class NotificationJmsEndpointConfig extends AbstractJmsEndpointConfig<NotificationMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public NotificationJmsEndpointConfig(
        ObjectMapper objectMapper,
        MessageProcessor<NotificationMessage> listenerMessageProcessor,
        RetryTemplate jmsRetryTemplate,
        MessagingProperties messagingProperties,
        MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
            "notificationListener",
            messagingProperties.consumerDestination(messagingProperties.queue().notification()),
            messagingProperties.queue().notification(),
            messagingProperties.routingKey().notification(),
            messagingConcurrencyProperties.notifications(),
            NotificationMessage.class
        );
    }
}
