package com.czertainly.core.messaging.jms.producers;

import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.model.AuditLogMessage;
import lombok.AllArgsConstructor;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
@AllArgsConstructor
public class AuditLogsProducer {
    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    public void produceMessage(@NonNull final AuditLogMessage auditLogMessage) {
        Objects.requireNonNull(auditLogMessage, "Audit log message cannot be null");

        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(
                    messagingProperties.produceDestinationAuditLogs(),
                    auditLogMessage,
                    message -> {
                        message.setJMSType(messagingProperties.routingKey().auditLogs());
                        return message;
                    });
            return null;
        });
    }
}
