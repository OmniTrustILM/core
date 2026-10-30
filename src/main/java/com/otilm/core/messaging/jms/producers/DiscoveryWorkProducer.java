package com.otilm.core.messaging.jms.producers;

import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import java.util.Objects;
import lombok.AllArgsConstructor;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class DiscoveryWorkProducer {
    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    /**
     * Sends a work-tick message immediately. The backoff cadence is owned by the {@code discovery_work} due-time table
     * and its sweep, which only enqueues a tick once it is due — so this producer carries no delivery delay.
     */
    public void produceMessage(@NonNull final DiscoveryWorkMessage workMessage) {
        Objects.requireNonNull(workMessage, "Discovery work message cannot be null");

        producerRetryTemplate.execute(context -> {
            jmsTemplate
                    .convertAndSend(messagingProperties.produceDestinationProviderDiscoveryWork(), workMessage,
                            message -> {
                                message.setJMSType(messagingProperties.routingKey().providerDiscoveryWork());
                                return message;
                            });
            return null;
        });
    }
}
