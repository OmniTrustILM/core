package com.czertainly.core.messaging.jms.producers;

import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.model.ValidationMessage;
import lombok.AllArgsConstructor;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
@AllArgsConstructor
public class ValidationProducer {
    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    public void produceMessage(@NonNull final ValidationMessage validationMessage) {
        Objects.requireNonNull(validationMessage, "Validation message cannot be null");
        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(
                    messagingProperties.produceDestinationValidation(),
                    validationMessage,
                    message -> {
                        message.setJMSType(messagingProperties.routingKey().validation());
                        return message;
                    });
            return null;
        });
    }
}
