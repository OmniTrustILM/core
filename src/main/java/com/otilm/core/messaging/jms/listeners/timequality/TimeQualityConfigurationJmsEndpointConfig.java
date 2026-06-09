package com.otilm.core.messaging.jms.listeners.timequality;

import com.otilm.api.model.messaging.timequality.TimeQualityConfigRequest;
import com.otilm.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
@ConditionalOnProperty(name = "messaging.time-quality.enabled", havingValue = "true")
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
