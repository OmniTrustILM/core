package com.czertainly.core.messaging.jms.producers;

import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.model.ActionMessage;
import lombok.AllArgsConstructor;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
@AllArgsConstructor
public class ActionProducer {
    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    public void produceMessage(@NonNull final ActionMessage actionMessage) {
        Objects.requireNonNull(actionMessage, "Action message cannot be null");

        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(
                    messagingProperties.produceDestinationActions(),
                    actionMessage,
                    message -> {
                        message.setJMSType(messagingProperties.routingKey().actions());
                        return message;
                    });
            return null;
        });
    }
}
