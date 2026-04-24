package com.czertainly.core.messaging.jms.listeners.scheduler;

import com.czertainly.api.model.scheduler.SchedulerJobExecutionMessage;
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
public class SchedulerJmsEndpointConfig extends AbstractJmsEndpointConfig<SchedulerJobExecutionMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public SchedulerJmsEndpointConfig(
        ObjectMapper objectMapper,
        MessageProcessor<SchedulerJobExecutionMessage> listenerMessageProcessor,
        RetryTemplate jmsRetryTemplate,
        MessagingProperties messagingProperties,
        MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
            "schedulerListener",
            messagingProperties.consumerDestination(messagingProperties.queue().scheduler()),
            messagingProperties.queue().scheduler(),
            messagingProperties.routingKey().scheduler(),
            messagingConcurrencyProperties.scheduler(),
            SchedulerJobExecutionMessage.class
        );
    }
}
