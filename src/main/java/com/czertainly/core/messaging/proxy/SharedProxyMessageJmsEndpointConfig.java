package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.AbstractJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

/**
 * JMS endpoint configuration for receiving fire-and-forget proxy messages on the shared queue.
 * All Core instances share this queue for messages like health checks and connector registration.
 */
@Component
@Profile("!test")
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class SharedProxyMessageJmsEndpointConfig extends AbstractJmsEndpointConfig<ProxyMessage> {

    private final ProxyProperties proxyProperties;

    public SharedProxyMessageJmsEndpointConfig(
            ObjectMapper objectMapper,
            @Qualifier("sharedProxyMessageListener") MessageProcessor<ProxyMessage> listenerMessageProcessor,
            RetryTemplate jmsRetryTemplate,
            MessagingProperties messagingProperties,
            ProxyProperties proxyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.proxyProperties = proxyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
                "sharedProxyMessageListener",
                messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS
                        ? proxyProperties.exchange()
                        : "/queues/" + proxyProperties.responseQueue(),
                proxyProperties.responseQueue(),
                null,
                proxyProperties.concurrency(),
                ProxyMessage.class
        );
    }
}
