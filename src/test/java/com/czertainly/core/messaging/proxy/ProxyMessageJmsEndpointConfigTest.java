package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProxyMessageJmsEndpointConfigTest {

    @Mock
    private MessageProcessor<ProxyMessage> instanceProcessor;

    @Mock
    private MessageProcessor<ProxyMessage> sharedProcessor;

    @Mock
    private MessagingProperties messagingProperties;

    @Mock
    private RetryTemplate retryTemplate;

    private ProxyProperties proxyProperties;

    @BeforeEach
    void setUp() {
        proxyProperties = new ProxyProperties(
                "test-proxy-exchange",
                "test-core-queue",
                "test-instance-0",
                Duration.ofSeconds(30),
                1000,
                null
        );
    }

    @Nested
    class InstanceEndpointTests {

        @Test
        void listenerEndpoint_withServiceBus_usesInstanceIdAsSubscription() {
            when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

            InstanceProxyMessageJmsEndpointConfig config = new InstanceProxyMessageJmsEndpointConfig(
                    new ObjectMapper(), instanceProcessor, retryTemplate, messagingProperties, proxyProperties);
            SimpleJmsListenerEndpoint endpoint = config.listenerEndpoint();

            assertThat(endpoint.getDestination()).isEqualTo("test-proxy-exchange");
            assertThat(endpoint.getSubscription()).isEqualTo("test-instance-0");
        }

        @Test
        void listenerEndpoint_withRabbitMQ_usesInstanceQueuePath() {
            when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

            InstanceProxyMessageJmsEndpointConfig config = new InstanceProxyMessageJmsEndpointConfig(
                    new ObjectMapper(), instanceProcessor, retryTemplate, messagingProperties, proxyProperties);
            SimpleJmsListenerEndpoint endpoint = config.listenerEndpoint();

            assertThat(endpoint.getDestination()).isEqualTo("/queues/test-instance-0");
            assertThat(endpoint.getSubscription()).isNull();
        }
    }

    @Nested
    class SharedEndpointTests {

        @Test
        void listenerEndpoint_withServiceBus_usesResponseQueueAsSubscription() {
            when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

            SharedProxyMessageJmsEndpointConfig config = new SharedProxyMessageJmsEndpointConfig(
                    new ObjectMapper(), sharedProcessor, retryTemplate, messagingProperties, proxyProperties);
            SimpleJmsListenerEndpoint endpoint = config.listenerEndpoint();

            assertThat(endpoint.getDestination()).isEqualTo("test-proxy-exchange");
            assertThat(endpoint.getSubscription()).isEqualTo("test-core-queue");
        }

        @Test
        void listenerEndpoint_withRabbitMQ_usesResponseQueuePath() {
            when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

            SharedProxyMessageJmsEndpointConfig config = new SharedProxyMessageJmsEndpointConfig(
                    new ObjectMapper(), sharedProcessor, retryTemplate, messagingProperties, proxyProperties);
            SimpleJmsListenerEndpoint endpoint = config.listenerEndpoint();

            assertThat(endpoint.getDestination()).isEqualTo("/queues/test-core-queue");
            assertThat(endpoint.getSubscription()).isNull();
        }
    }
}
