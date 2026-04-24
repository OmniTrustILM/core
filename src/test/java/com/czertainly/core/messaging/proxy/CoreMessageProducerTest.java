package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ConnectorRequest;
import com.czertainly.api.clients.mq.model.CoreMessage;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.support.RetryTemplate;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link CoreMessageProducer}.
 * Tests message sending with different broker configurations.
 */
@ExtendWith(MockitoExtension.class)
class CoreMessageProducerTest {

    @Mock
    private JmsTemplate jmsTemplate;

    @Mock
    private MessagingProperties messagingProperties;

    @Mock
    private RetryTemplate retryTemplate;

    @Captor
    private ArgumentCaptor<MessagePostProcessor> postProcessorCaptor;

    private ProxyProperties proxyProperties;
    private CoreMessageProducer producer;

    @BeforeEach
    void setUp() throws Exception {
        proxyProperties = new ProxyProperties(
                "czertainly-proxy",  // exchange
                "core",              // responseQueue
                "test-instance",     // instanceId
                Duration.ofSeconds(30),
                1000,
                null
        );

        // Default: execute callback immediately for RetryTemplate
        when(retryTemplate.execute(any())).thenAnswer(invocation -> {
            RetryCallback<?, ?> callback = invocation.getArgument(0);
            return callback.doWithRetry(null);
        });

        producer = new CoreMessageProducer(jmsTemplate, proxyProperties, messagingProperties, retryTemplate);
    }

    // ==================== ServiceBus Tests ====================

    @Test
    void send_withServiceBus_usesTopicDirectly() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        CoreMessage message = createCoreMessage("corr-1");
        producer.send(message, "proxy-001");

        verify(jmsTemplate).convertAndSend(
                eq("czertainly-proxy"),
                eq(message),
                any(MessagePostProcessor.class)
        );
    }

    @Test
    void send_withServiceBus_setsJMSTypeToRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        CoreMessage message = createCoreMessage("corr-1");
        producer.send(message, "proxy-001");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                eq(message),
                postProcessorCaptor.capture()
        );

        // Verify the post processor sets JMSType correctly
        Message mockMessage = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage);

        verify(mockMessage).setJMSType("coremessage.proxy-001");
    }

    @Test
    void send_withServiceBus_setsJMSCorrelationID() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        CoreMessage message = createCoreMessage("my-correlation-id");
        producer.send(message, "proxy-001");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                eq(message),
                postProcessorCaptor.capture()
        );

        Message mockMessage = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage);

        verify(mockMessage).setJMSCorrelationID("my-correlation-id");
    }

    // ==================== RabbitMQ Tests ====================

    @Test
    void send_withRabbitMQ_prefixesExchangeAndAppendsRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        CoreMessage message = createCoreMessage("corr-1");
        producer.send(message, "proxy-002");

        verify(jmsTemplate).convertAndSend(
                eq("/exchanges/czertainly-proxy/coremessage.proxy-002"),
                eq(message),
                any(MessagePostProcessor.class)
        );
    }

    @Test
    void send_withRabbitMQ_setsCorrectRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        CoreMessage message = createCoreMessage("corr-1");
        producer.send(message, "my-proxy-instance");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                eq(message),
                postProcessorCaptor.capture()
        );

        Message mockMessage = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage);

        verify(mockMessage).setJMSType("coremessage.my-proxy-instance");
    }

    // ==================== Retry Tests ====================

    @Test
    void send_usesRetryTemplate() throws Exception {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        CoreMessage message = createCoreMessage("corr-1");
        producer.send(message, "proxy-001");

        verify(retryTemplate).execute(any());
        verify(jmsTemplate).convertAndSend(
                any(String.class),
                eq(message),
                any(MessagePostProcessor.class)
        );
    }

    // ==================== Different ProxyId Tests ====================

    @Test
    void send_withDifferentProxyIds_usesCorrectRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        // First request
        producer.send(createCoreMessage("corr-1"), "proxy-alpha");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                any(CoreMessage.class),
                postProcessorCaptor.capture()
        );

        Message mockMessage1 = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage1);
        verify(mockMessage1).setJMSType("coremessage.proxy-alpha");

        // Reset for second request
        reset(jmsTemplate);

        // Second request with different proxyId
        producer.send(createCoreMessage("corr-2"), "proxy-beta");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                any(CoreMessage.class),
                postProcessorCaptor.capture()
        );

        Message mockMessage2 = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage2);
        verify(mockMessage2).setJMSType("coremessage.proxy-beta");
    }

    @Test
    void send_preservesMessageCorrelationId() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        CoreMessage message = createCoreMessage("unique-correlation-123");
        producer.send(message, "proxy-001");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                eq(message),
                postProcessorCaptor.capture()
        );

        Message mockMessage = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage);

        verify(mockMessage).setJMSCorrelationID("unique-correlation-123");
    }

    // ==================== Reply-To Tests ====================

    @Test
    void send_setsJMSReplyToWithInstanceId() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        CoreMessage message = createCoreMessage("corr-1");
        producer.send(message, "proxy-001");

        verify(jmsTemplate).convertAndSend(
                any(String.class),
                eq(message),
                postProcessorCaptor.capture()
        );

        Message mockMessage = mock(Message.class);
        postProcessorCaptor.getValue().postProcessMessage(mockMessage);

        ArgumentCaptor<jakarta.jms.Destination> destCaptor = ArgumentCaptor.forClass(jakarta.jms.Destination.class);
        verify(mockMessage).setJMSReplyTo(destCaptor.capture());
        assertThat(destCaptor.getValue()).isInstanceOf(org.apache.qpid.jms.JmsQueue.class);
        assertThat(destCaptor.getValue().toString()).contains("test-instance");
    }

    // ==================== Helper Methods ====================

    private CoreMessage createCoreMessage(String correlationId) {
        return CoreMessage.builder()
                .correlationId(correlationId)
                .messageType("POST:/v1/test")
                .timestamp(Instant.now())
                .connectorRequest(ConnectorRequest.builder()
                        .connectorUrl("http://connector.example.com")
                        .method("POST")
                        .path("/v1/test")
                        .timeout("30s")
                        .build())
                .build();
    }
}
