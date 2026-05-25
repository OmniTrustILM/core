package com.czertainly.core.messaging.jms.listeners.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityResultMessage;
import com.czertainly.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class TimeQualityResultsJmsEndpointConfig extends AbstractJmsEndpointConfig<TimeQualityResultMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public TimeQualityResultsJmsEndpointConfig(
            ObjectMapper objectMapper,
            MessageProcessor<TimeQualityResultMessage> listenerMessageProcessor,
            RetryTemplate jmsRetryTemplate,
            MessagingProperties messagingProperties,
            MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
                "timeQualityResultsListener",
                messagingProperties.consumerDestination(messagingProperties.queue().timeQualityResults()),
                messagingProperties.queue().timeQualityResults(),
                messagingProperties.routingKey().timeQualityResults(),
                messagingConcurrencyProperties.timeQualityResults(),
                TimeQualityResultMessage.class
        );
    }
}
