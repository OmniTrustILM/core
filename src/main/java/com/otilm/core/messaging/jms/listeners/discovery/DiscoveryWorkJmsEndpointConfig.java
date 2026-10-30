package com.otilm.core.messaging.jms.listeners.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class DiscoveryWorkJmsEndpointConfig extends AbstractJmsEndpointConfig<DiscoveryWorkMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public DiscoveryWorkJmsEndpointConfig(ObjectMapper objectMapper,
            MessageProcessor<DiscoveryWorkMessage> listenerMessageProcessor, RetryTemplate jmsRetryTemplate,
            MessagingProperties messagingProperties, MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal("discoveryWorkListener",
                messagingProperties.consumerDestination(messagingProperties.queue().providerDiscoveryWork()),
                messagingProperties.queue().providerDiscoveryWork(),
                messagingProperties.routingKey().providerDiscoveryWork(),
                messagingConcurrencyProperties.providerDiscoveryWork(), DiscoveryWorkMessage.class);
    }
}
