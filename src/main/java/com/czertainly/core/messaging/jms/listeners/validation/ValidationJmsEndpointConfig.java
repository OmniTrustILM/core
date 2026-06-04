package com.czertainly.core.messaging.jms.listeners.validation;

import com.czertainly.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.messaging.model.ValidationMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class ValidationJmsEndpointConfig extends AbstractJmsEndpointConfig<ValidationMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public ValidationJmsEndpointConfig(
        ObjectMapper objectMapper,
        MessageProcessor<ValidationMessage> listenerMessageProcessor,
        RetryTemplate jmsRetryTemplate,
        MessagingProperties messagingProperties,
        MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
            "validationListener",
            messagingProperties.consumerDestination(messagingProperties.queue().validation()),
            messagingProperties.queue().validation(),
            messagingProperties.routingKey().validation(),
            messagingConcurrencyProperties.validation(),
            ValidationMessage.class
        );
    }
}
