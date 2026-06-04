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
 * JMS endpoint configuration for receiving proxy responses on the per-instance queue.
 * Each Core instance listens on its own queue identified by {@link ProxyProperties#instanceId()}.
 */
@Component
@Profile("!test")
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class InstanceProxyMessageJmsEndpointConfig extends AbstractJmsEndpointConfig<ProxyMessage> {

    private final ProxyProperties proxyProperties;

    public InstanceProxyMessageJmsEndpointConfig(
            ObjectMapper objectMapper,
            @Qualifier("instanceProxyMessageListener") MessageProcessor<ProxyMessage> listenerMessageProcessor,
            RetryTemplate jmsRetryTemplate,
            MessagingProperties messagingProperties,
            ProxyProperties proxyProperties) {
        super(objectMapper, listenerMessageProcessor, jmsRetryTemplate, messagingProperties);
        this.proxyProperties = proxyProperties;
    }

    @Override
    public SimpleJmsListenerEndpoint listenerEndpoint() {
        return listenerEndpointInternal(
                "instanceProxyMessageListener",
                messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS
                        ? proxyProperties.exchange()
                        : "/queues/" + proxyProperties.instanceId(),
                proxyProperties.instanceId(),
                null,
                proxyProperties.concurrency(),
                ProxyMessage.class
        );
    }
}
