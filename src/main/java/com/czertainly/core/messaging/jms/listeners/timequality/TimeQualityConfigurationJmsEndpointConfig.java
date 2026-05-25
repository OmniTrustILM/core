package com.czertainly.core.messaging.jms.listeners.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityConfigRequest;
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
public class TimeQualityConfigurationJmsEndpointConfig extends AbstractJmsEndpointConfig<TimeQualityConfigRequest> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public TimeQualityConfigurationJmsEndpointConfig(
            ObjectMapper objectMapper,
            MessageProcessor<TimeQualityConfigRequest> listenerMessageProcessor,
            RetryTemplate jmsRetryTemplate,
            MessagingProperties messagingProperties,
            MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
                "timeQualityConfigRequestListener",
                messagingProperties.consumerDestination(messagingProperties.queue().timeQualityConfigRequest()),
                messagingProperties.queue().timeQualityConfigRequest(),
                messagingProperties.routingKey().timeQualityConfigRequest(),
                messagingConcurrencyProperties.timeQualityConfigRequest(),
                TimeQualityConfigRequest.class
        );
    }
}
