package com.otilm.core.messaging.jms.producers;

import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import lombok.AllArgsConstructor;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Objects;

@Component
@AllArgsConstructor
public class CertificateStatusPollProducer {
    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;
    private final StatusPollProperties statusPollProperties;

    public void produceMessage(@NonNull final CertificateStatusPollMessage pollMessage) {
        Objects.requireNonNull(pollMessage, "Poll message cannot be null");

        Duration delay = statusPollProperties.scheduleFor(pollMessage.op()).delayFor(pollMessage.attempt());

        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(
                    messagingProperties.produceDestinationProviderStatusPoll(),
                    pollMessage,
                    message -> {
                        message.setJMSType(messagingProperties.routingKey().providerStatusPoll());
                        message.setLongProperty("x-delay", delay.toMillis());
                        return message;
                    });
            return null;
        });
    }
}
