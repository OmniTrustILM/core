package com.otilm.core.messaging.proxy;

import com.otilm.api.clients.mq.model.ConnectorRequest;
import com.otilm.api.clients.mq.model.CoreMessage;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import jakarta.jms.DeliveryMode;
import jakarta.jms.Destination;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.MessageProducer;
import jakarta.jms.Session;
import java.time.Duration;
import java.time.Instant;
import org.apache.qpid.jms.JmsQueue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.UncategorizedJmsException;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.ProducerCallback;
import org.springframework.jms.support.converter.MessageConverter;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.support.RetryTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CoreMessageProducer}. Tests message sending with different broker configurations.
 */
@ExtendWith(MockitoExtension.class)
class CoreMessageProducerTest {

    private static final Duration TIME_TO_LIVE = Duration.ofSeconds(30);

    @Mock
    private JmsTemplate jmsTemplate;

    @Mock
    private MessagingProperties messagingProperties;

    @Mock
    private RetryTemplate retryTemplate;

    @Mock
    private MessageConverter messageConverter;

    @Mock
    private Session session;

    @Mock
    private MessageProducer jmsProducer;

    @Mock
    private Message jmsMessage;

    @Captor
    private ArgumentCaptor<ProducerCallback<Object>> sendCaptor;

    private ProxyProperties proxyProperties;
    private CoreMessageProducer producer;

    @BeforeEach
    void setUp() {
        proxyProperties = new ProxyProperties("ilm-proxy", // exchange
                "core", // responseQueue
                "test-instance", // instanceId
                Duration.ofSeconds(30), 1000, null);

        // Default: execute callback immediately for RetryTemplate
        lenient().when(retryTemplate.execute(any())).thenAnswer(invocation -> {
            RetryCallback<?, ?> callback = invocation.getArgument(0);
            return callback.doWithRetry(null);
        });

        producer = new CoreMessageProducer(jmsTemplate, proxyProperties, messagingProperties, retryTemplate,
                messageConverter);
    }

    // ==================== ServiceBus Tests ====================

    @Test
    void send_withServiceBus_usesTopicDirectly() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        runSendTo("ilm-proxy");
        verify(jmsProducer).send(same(jmsMessage), anyInt(), anyInt(), anyLong());
    }

    @Test
    void send_withServiceBus_setsJMSTypeToRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        runSendTo("ilm-proxy");
        verify(jmsMessage).setJMSType("coremessage.proxy-001");
    }

    @Test
    void send_withServiceBus_setsJMSCorrelationID() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        producer.send(createCoreMessage("my-correlation-id"), "proxy-001", TIME_TO_LIVE);

        runSendTo("ilm-proxy");
        verify(jmsMessage).setJMSCorrelationID("my-correlation-id");
    }

    // ==================== RabbitMQ Tests ====================

    @Test
    void send_withRabbitMQ_prefixesExchangeAndAppendsRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        producer.send(createCoreMessage("corr-1"), "proxy-002", TIME_TO_LIVE);

        runSendTo("/exchanges/ilm-proxy/coremessage.proxy-002");
        verify(jmsProducer).send(same(jmsMessage), anyInt(), anyInt(), anyLong());
    }

    @Test
    void send_withRabbitMQ_setsCorrectRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        producer.send(createCoreMessage("corr-1"), "my-proxy-instance", TIME_TO_LIVE);

        runSendTo("/exchanges/ilm-proxy/coremessage.my-proxy-instance");
        verify(jmsMessage).setJMSType("coremessage.my-proxy-instance");
    }

    // ==================== Time to Live Tests ====================

    @ParameterizedTest
    @CsvSource({"SERVICEBUS, ilm-proxy", "RABBITMQ, /exchanges/ilm-proxy/coremessage.proxy-001"})
    void send_expiresTheMessageWhenTheRequestsTimeRunsOut(MessagingProperties.BrokerType brokerType, String destination)
            throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(brokerType);

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        runSendTo(destination);
        verify(jmsProducer).send(same(jmsMessage), anyInt(), anyInt(), longThat(ttl -> ttl > 25_000 && ttl <= 30_000));
    }

    @Test
    void send_keepsTheProducersDeliveryModeAndPriority() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);
        when(jmsProducer.getDeliveryMode()).thenReturn(DeliveryMode.NON_PERSISTENT);
        when(jmsProducer.getPriority()).thenReturn(7);

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        runSendTo("/exchanges/ilm-proxy/coremessage.proxy-001");
        verify(jmsProducer).send(same(jmsMessage), eq(DeliveryMode.NON_PERSISTENT), eq(7), anyLong());
    }

    @Test
    void send_givesARetriedSendOnlyTheTimeThatIsLeft() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);
        RetryTemplate retrying = RetryTemplate
                .builder()
                .maxAttempts(2)
                .fixedBackoff(200)
                .retryOn(UncategorizedJmsException.class)
                .build();
        CoreMessageProducer retryingProducer = new CoreMessageProducer(jmsTemplate, proxyProperties,
                messagingProperties, retrying, messageConverter);
        when(jmsTemplate.execute(anyString(), ArgumentMatchers.<ProducerCallback<Object>>any()))
                .thenThrow(new UncategorizedJmsException("broker unavailable"))
                .thenReturn(null);

        retryingProducer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        verify(jmsTemplate, times(2)).execute(eq("/exchanges/ilm-proxy/coremessage.proxy-001"), sendCaptor.capture());
        when(messageConverter.toMessage(any(CoreMessage.class), same(session))).thenReturn(jmsMessage);
        sendCaptor.getAllValues().getLast().doInJms(session, jmsProducer);
        verify(jmsProducer).send(same(jmsMessage), anyInt(), anyInt(), longThat(ttl -> ttl > 25_000 && ttl <= 29_800));
    }

    @Test
    void send_givesTheMessageTheTimeLeftWhenItGoesOut() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);
        Instant sentAt = Instant.now();

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);
        // The template may take a while to open a connection before it runs the send
        await().until(() -> Instant.now().isAfter(sentAt.plusMillis(300)));

        runSendTo("/exchanges/ilm-proxy/coremessage.proxy-001");
        verify(jmsProducer).send(same(jmsMessage), anyInt(), anyInt(), longThat(ttl -> ttl > 25_000 && ttl <= 29_800));
    }

    @Test
    void send_doesNotSendWhenTheTimeRunsOutWhileTheConnectionOpens() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);
        lenient().when(messageConverter.toMessage(any(CoreMessage.class), same(session))).thenReturn(jmsMessage);
        Instant sentAt = Instant.now();

        producer.send(createCoreMessage("corr-1"), "proxy-001", Duration.ofMillis(50));
        await().until(() -> Instant.now().isAfter(sentAt.plusMillis(150)));

        verify(jmsTemplate).execute(eq("/exchanges/ilm-proxy/coremessage.proxy-001"), sendCaptor.capture());
        sendCaptor.getValue().doInJms(session, jmsProducer);
        verifyNoInteractions(messageConverter, jmsProducer);
    }

    @ParameterizedTest
    @ValueSource(longs = {-1_000_000_000L, 0L, 999_999L})
    void send_doesNotSendARequestWhoseTimeHasRunOut(long timeToLiveNanos) {
        producer.send(createCoreMessage("corr-1"), "proxy-001", Duration.ofNanos(timeToLiveNanos));

        verifyNoInteractions(jmsTemplate);
    }

    @Test
    void send_refusesAMissingTimeToLive() {
        CoreMessage message = createCoreMessage("corr-1");

        assertThatThrownBy(() -> producer.send(message, "proxy-001", null)).isInstanceOf(NullPointerException.class);
        verifyNoInteractions(jmsTemplate);
    }

    // ==================== Retry Tests ====================

    @Test
    void send_usesRetryTemplate() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        verify(retryTemplate).execute(any());
        runSendTo("ilm-proxy");
    }

    // ==================== Different ProxyId Tests ====================

    @Test
    void send_withDifferentProxyIds_usesCorrectRoutingKey() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        producer.send(createCoreMessage("corr-1"), "proxy-alpha", TIME_TO_LIVE);
        producer.send(createCoreMessage("corr-2"), "proxy-beta", TIME_TO_LIVE);

        runSendTo("/exchanges/ilm-proxy/coremessage.proxy-alpha");
        verify(jmsMessage).setJMSType("coremessage.proxy-alpha");
        runSendTo("/exchanges/ilm-proxy/coremessage.proxy-beta");
        verify(jmsMessage).setJMSType("coremessage.proxy-beta");
    }

    @Test
    void send_preservesMessageCorrelationId() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);

        producer.send(createCoreMessage("unique-correlation-123"), "proxy-001", TIME_TO_LIVE);

        runSendTo("ilm-proxy");
        verify(jmsMessage).setJMSCorrelationID("unique-correlation-123");
    }

    // ==================== Reply-To Tests ====================

    @Test
    void send_setsJMSReplyToWithInstanceId() throws JMSException {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        producer.send(createCoreMessage("corr-1"), "proxy-001", TIME_TO_LIVE);

        runSendTo("/exchanges/ilm-proxy/coremessage.proxy-001");
        ArgumentCaptor<Destination> replyTo = ArgumentCaptor.forClass(Destination.class);
        verify(jmsMessage).setJMSReplyTo(replyTo.capture());
        assertThat(replyTo.getValue()).isInstanceOf(JmsQueue.class);
        assertThat(replyTo.getValue().toString()).contains("test-instance");
    }

    // ==================== Helper Methods ====================

    /** Runs the send the producer handed to the template, as the template would, against the mocked session. */
    private void runSendTo(String destination) throws JMSException {
        verify(jmsTemplate).execute(eq(destination), sendCaptor.capture());
        when(messageConverter.toMessage(any(CoreMessage.class), same(session))).thenReturn(jmsMessage);
        sendCaptor.getValue().doInJms(session, jmsProducer);
    }

    private CoreMessage createCoreMessage(String correlationId) {
        return CoreMessage
                .builder()
                .correlationId(correlationId)
                .messageType("POST:/v1/test")
                .timestamp(Instant.now())
                .connectorRequest(ConnectorRequest
                        .builder()
                        .connectorUrl("http://connector.example.com")
                        .method("POST")
                        .path("/v1/test")
                        .timeout("30s")
                        .build())
                .build();
    }
}
