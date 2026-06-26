package com.otilm.core.messaging.jms.producers;

import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import lombok.AllArgsConstructor;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
@AllArgsConstructor
public class CertificateStatusPollProducer {
    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    /**
     * Sends a poll message immediately. The backoff cadence is owned by the due-time table and
     * {@link com.otilm.core.messaging.jms.listeners.poll.CertificateStatusPollSweeper}, which only enqueues
     * a poll once it is due — so this producer carries no delivery delay.
     */
    public void produceMessage(@NonNull final CertificateStatusPollMessage pollMessage) {
        Objects.requireNonNull(pollMessage, "Poll message cannot be null");

        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(
                    messagingProperties.produceDestinationProviderStatusPoll(),
                    pollMessage,
                    message -> {
                        message.setJMSType(messagingProperties.routingKey().providerStatusPoll());
                        return message;
                    });
            return null;
        });
    }
}
