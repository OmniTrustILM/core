package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;


@Component
@Profile("!test")
public class PollJmsEndpointConfig extends AbstractJmsEndpointConfig<CertificateStatusPollMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public PollJmsEndpointConfig(
            ObjectMapper objectMapper,
            MessageProcessor<CertificateStatusPollMessage> listenerMessageProcessor,
            RetryTemplate jmsRetryTemplate,
            MessagingProperties messagingProperties,
            MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
                "pollListener",
                messagingProperties.consumerDestination(messagingProperties.queue().providerStatusPoll()),
                messagingProperties.queue().providerStatusPoll(),
                messagingProperties.routingKey().providerStatusPoll(),
                messagingConcurrencyProperties.providerStatusPoll(),
                CertificateStatusPollMessage.class
        );
    }
}
