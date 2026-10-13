package com.otilm.core.messaging.jms.listeners.event;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.model.EventMessage;
import jakarta.jms.Session;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.jms.listener.AbstractMessageListenerContainer;
import org.springframework.jms.listener.MessageListenerContainer;
import org.springframework.messaging.MessagingException;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
@Slf4j
public class EventJmsEndpointConfig extends AbstractJmsEndpointConfig<EventMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public EventJmsEndpointConfig(ObjectMapper objectMapper, MessageProcessor<EventMessage> listenerMessageProcessor,
            @Qualifier("eventRetryTemplate") RetryTemplate eventRetryTemplate, MessagingProperties messagingProperties,
            MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, eventRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal("eventListener",
                messagingProperties.consumerDestination(messagingProperties.queue().event()),
                messagingProperties.queue().event(), messagingProperties.routingKey().event(),
                messagingConcurrencyProperties.events(), EventMessage.class);
    }

    @Override
    protected void configureListenerContainer(MessageListenerContainer listenerContainer) {
        if (listenerContainer instanceof AbstractMessageListenerContainer container) {
            if (messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
                container.setSessionTransacted(true);
            } else {
                // RabbitMQ's AMQP 1.0 transport has no transactions. Recover an unacknowledged delivery on failure.
                container.setSessionAcknowledgeMode(Session.CLIENT_ACKNOWLEDGE);
            }
        }
    }

    @Override
    protected void validateMessage(EventMessage message) {
        if (message == null || message.getEvent() == null || message.getResource() == null) {
            throw new IllegalArgumentException("Event and resource are required");
        }
    }

    @Override
    protected void handleProcessingFailure(String endpointId, Exception failure) {
        if (failure instanceof JsonProcessingException || failure instanceof IllegalArgumentException
                || failure instanceof DataIntegrityViolationException) {
            log.error("Discarding invalid event in endpoint '{}': {}", endpointId, failure.getClass().getSimpleName());
            return;
        }
        if (failure instanceof RuntimeException runtime) {
            throw runtime;
        }
        throw new MessagingException("Message processing failed in endpoint: " + endpointId, failure);
    }
}
