package com.otilm.core.messaging.jms.listeners.auditlogs;

import com.otilm.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;


@Component
@Profile("!test")
public class AuditLogsJmsEndpointConfig extends AbstractJmsEndpointConfig<AuditLogMessage> {

    private final MessagingConcurrencyProperties messagingConcurrencyProperties;

    public AuditLogsJmsEndpointConfig(
        ObjectMapper objectMapper,
        MessageProcessor<AuditLogMessage> listenerMessageProcessor,
        RetryTemplate jmsRetryTemplate,
        MessagingProperties messagingProperties,
        MessagingConcurrencyProperties messagingConcurrencyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.messagingConcurrencyProperties = messagingConcurrencyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
            "auditLogsListener",
            messagingProperties.consumerDestination(messagingProperties.queue().auditLogs()),
            messagingProperties.queue().auditLogs(),
            messagingProperties.routingKey().auditLogs(),
            messagingConcurrencyProperties.auditLogs(),
            AuditLogMessage.class
        );
    }
}
