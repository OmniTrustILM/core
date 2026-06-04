package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.CoreMessage;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.apache.qpid.jms.JmsQueue;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

/**
 * Produces core messages to the message queue for proxy consumption.
 * Sends requests to the appropriate proxy instance based on proxyId.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class CoreMessageProducer {

    private final JmsTemplate jmsTemplate;
    private final ProxyProperties proxyProperties;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    public CoreMessageProducer(
            JmsTemplate jmsTemplate,
            ProxyProperties proxyProperties,
            MessagingProperties messagingProperties,
            RetryTemplate producerRetryTemplate) {
        this.jmsTemplate = jmsTemplate;
        this.proxyProperties = proxyProperties;
        this.messagingProperties = messagingProperties;
        this.producerRetryTemplate = producerRetryTemplate;
        log.info("CoreMessageProducer initialized with exchange: {}", proxyProperties.exchange());
    }

    /**
     * Send a core message to the specified proxy instance.
     *
     * @param message The core message to send
     * @param proxyId The target proxy instance ID
     */
    public void send(CoreMessage message, String proxyId) {
        Objects.requireNonNull(message, "message must not be null");
        if (proxyId == null || proxyId.isBlank()) {
            throw new IllegalArgumentException("proxyId must not be null or blank");
        }

        String routingKey = proxyProperties.getRequestRoutingKey(proxyId);
        String destination = getDestination(routingKey);

        log.debug("Sending core message correlationId={} proxyId={} destination={} routingKey={}",
                message.getCorrelationId(), proxyId, destination, routingKey);

        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(
                    destination,
                    message,
                    msg -> {
                        // Azure-native: JMSType maps to Service Bus Label/Subject
                        // Use Label for routing - optimal with Correlation Filters
                        msg.setJMSType(routingKey);
                        // Set JMS correlation ID for request/response matching
                        msg.setJMSCorrelationID(message.getCorrelationId());
                        msg.setJMSReplyTo(new JmsQueue(proxyProperties.instanceId()));
                        return msg;
                    });

            log.debug("Sent core message correlationId={} routingKey={}",
                    message.getCorrelationId(), routingKey);
            return null;
        });
    }

    /**
     * Get the destination (topic/exchange) based on broker type.
     * For ServiceBus, we use the topic directly (routing handled via JMSType + Correlation Filters).
     * For RabbitMQ, we use the explicit {@code /exchanges/{exchange}/{routingKey}} form so the broker
     * routes without relying on implicit AMQP subject-to-routing-key fallback.
     */
    private String getDestination(String routingKey) {
        if (messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
            return proxyProperties.exchange();
        }

        return "/exchanges/" + proxyProperties.exchange() + "/" + routingKey;
    }
}
