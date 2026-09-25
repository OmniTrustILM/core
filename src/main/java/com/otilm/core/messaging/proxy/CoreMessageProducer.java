package com.otilm.core.messaging.proxy;

import com.otilm.api.clients.mq.model.CoreMessage;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.Session;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.apache.qpid.jms.JmsQueue;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.support.converter.MessageConverter;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

/**
 * Produces core messages to the message queue for proxy consumption. Sends requests to the appropriate proxy instance
 * based on proxyId.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class CoreMessageProducer {

    private final JmsTemplate jmsTemplate;
    private final ProxyProperties proxyProperties;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;
    private final MessageConverter messageConverter;

    public CoreMessageProducer(JmsTemplate jmsTemplate, ProxyProperties proxyProperties,
            MessagingProperties messagingProperties, RetryTemplate producerRetryTemplate,
            MessageConverter messageConverter) {
        this.jmsTemplate = jmsTemplate;
        this.proxyProperties = proxyProperties;
        this.messagingProperties = messagingProperties;
        this.producerRetryTemplate = producerRetryTemplate;
        this.messageConverter = messageConverter;
        log.info("CoreMessageProducer initialized with exchange: {}", proxyProperties.exchange());
    }

    /**
     * Send a core message to the specified proxy instance. The message expires on the broker when Core stops waiting
     * for it, so a proxy that picks it up late never executes it; a retried send carries only the time left, and is not
     * made once that has run out.
     *
     * @param message The core message to send
     * @param proxyId The target proxy instance ID
     * @param timeToLive How long Core waits for the request, counted from this call
     */
    public void send(CoreMessage message, String proxyId, Duration timeToLive) {
        Objects.requireNonNull(message, "message must not be null");
        if (proxyId == null || proxyId.isBlank()) {
            throw new IllegalArgumentException("proxyId must not be null or blank");
        }
        Instant expiry = Instant.now().plus(Objects.requireNonNull(timeToLive, "timeToLive must not be null"));

        String routingKey = proxyProperties.getRequestRoutingKey(proxyId);
        String destination = getDestination(routingKey);

        log
                .debug("Sending core message correlationId={} proxyId={} destination={} routingKey={}",
                        message.getCorrelationId(), proxyId, destination, routingKey);

        producerRetryTemplate.execute(context -> {
            sendBefore(expiry, message, destination, routingKey);
            return null;
        });
    }

    private void sendBefore(Instant expiry, CoreMessage message, String destination, String routingKey) {
        // An attempt already out of time opens no connection
        if (millisLeft(expiry) < 1) {
            logOutOfTime(message, routingKey);
            return;
        }
        jmsTemplate.execute(destination, (session, jmsProducer) -> {
            // Opening the connection can take a while, so the time to live is what is left now
            long timeToLive = millisLeft(expiry);
            if (timeToLive < 1) {
                logOutOfTime(message, routingKey);
                return null;
            }
            // The provider overwrites an expiry set on the message, so the time to live goes with the send
            jmsProducer
                    .send(requestMessage(message, routingKey, session), jmsProducer.getDeliveryMode(),
                            jmsProducer.getPriority(), timeToLive);
            log.debug("Sent core message correlationId={} routingKey={}", message.getCorrelationId(), routingKey);
            return null;
        });
    }

    private Message requestMessage(CoreMessage message, String routingKey, Session session) throws JMSException {
        Message jmsMessage = messageConverter.toMessage(message, session);
        // Azure-native: JMSType maps to Service Bus Label/Subject
        // Use Label for routing - optimal with Correlation Filters
        jmsMessage.setJMSType(routingKey);
        // Set JMS correlation ID for request/response matching
        jmsMessage.setJMSCorrelationID(message.getCorrelationId());
        jmsMessage.setJMSReplyTo(new JmsQueue(proxyProperties.instanceId()));
        return jmsMessage;
    }

    /** Milliseconds left before the expiry. Below one nothing is sent: a time to live of zero never expires. */
    private static long millisLeft(Instant expiry) {
        return Duration.between(Instant.now(), expiry).toMillis();
    }

    private static void logOutOfTime(CoreMessage message, String routingKey) {
        log
                .warn("Not sending core message correlationId={} routingKey={}: its time to live ran out",
                        message.getCorrelationId(), routingKey);
    }

    /**
     * Get the destination (topic/exchange) based on broker type. For ServiceBus, we use the topic directly (routing
     * handled via JMSType + Correlation Filters). For RabbitMQ, we use the explicit
     * {@code /exchanges/{exchange}/{routingKey}} form so the broker routes without relying on implicit AMQP
     * subject-to-routing-key fallback.
     */
    private String getDestination(String routingKey) {
        if (messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
            return proxyProperties.exchange();
        }

        return "/exchanges/" + proxyProperties.exchange() + "/" + routingKey;
    }
}
