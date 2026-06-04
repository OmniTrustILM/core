package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.core.messaging.jms.configuration.JmsRetryListener;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.jms.JMSException;
import jakarta.jms.TextMessage;
import org.slf4j.Logger;
import org.springframework.jms.JmsException;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.jms.listener.DefaultMessageListenerContainer;
import org.springframework.jms.listener.MessageListenerContainer;
import org.springframework.lang.NonNull;
import org.springframework.messaging.MessagingException;
import org.springframework.retry.support.RetryTemplate;

import java.io.IOException;

import static org.slf4j.LoggerFactory.getLogger;

public abstract class AbstractJmsEndpointConfig<T> {

    private static final Logger logger = getLogger(AbstractJmsEndpointConfig.class);
    private static final String ROUTING_KEY = "routingKey";
    protected final MessageProcessor<T> listenerMessageProcessor;
    protected final RetryTemplate jmsRetryTemplate;
    protected final MessagingProperties messagingProperties;
    private final ObjectMapper objectMapper;

    public AbstractJmsEndpointConfig(ObjectMapper objectMapper, MessageProcessor<T> listenerMessageProcessor, RetryTemplate jmsRetryTemplate, MessagingProperties messagingProperties) {
        this.objectMapper = objectMapper;
        this.listenerMessageProcessor = listenerMessageProcessor;
        this.jmsRetryTemplate = jmsRetryTemplate;
        this.messagingProperties = messagingProperties;
    }

    public abstract SimpleJmsListenerEndpoint listenerEndpoint();

    /**
     *
     * @param endpointId   unique id for the endpoint
     * @param destination  queue path for RabbitMQ (/queues/name), or Topic name for Azure ServiceBus
     * @param subscription subscription name (Azure ServiceBus only; ignored for RabbitMQ)
     * @param routingKey   routing key used as JMS message selector (Azure ServiceBus only; for RabbitMQ filtering is done by broker binding)
     * @param concurrency  number of threads
     * @param messageClass type of message to be processed
     * @return endpoint to register in Spring context
     */
    public SimpleJmsListenerEndpoint listenerEndpointInternal(String endpointId,
                                                              String destination,
                                                              String subscription,
                                                              String routingKey,
                                                              String concurrency,
                                                              Class<T> messageClass) {
        logger.debug("Configuring JMS listener endpoint: id={}, destination={}, routingKey={}, broker={}, vhost={}",
            endpointId, destination, routingKey, messagingProperties.brokerType(), messagingProperties.virtualHost());

        SimpleJmsListenerEndpoint endpoint;
        if (messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
            endpoint = new SimpleJmsListenerEndpoint() {
                @Override
                public void setupListenerContainer(@NonNull MessageListenerContainer listenerContainer) {
                    super.setupListenerContainer(listenerContainer);
                    if (listenerContainer instanceof DefaultMessageListenerContainer container) {
                        container.setSubscriptionShared(true);// Shared must be set to allow concurrency
                        container.setSubscriptionDurable(true);
                        container.setDurableSubscriptionName(subscription);
                    }
                }
            };
            endpoint.setSubscription(subscription);

            if (routingKey != null && !routingKey.isBlank()) {
                endpoint.setSelector(ROUTING_KEY + " = '" + routingKey + "'");
            }
        } else {
            endpoint = new SimpleJmsListenerEndpoint();
        }

        endpoint.setId(endpointId);

        endpoint.setDestination(destination);
        endpoint.setConcurrency(concurrency);

        endpoint.setMessageListener(jmsMessage -> {
            logger.debug(">>> RECEIVED MESSAGE in endpoint: {}", endpointId);
            jmsRetryTemplate.execute(context -> {
                try {
                    context.setAttribute(JmsRetryListener.ENDPOINT_ID_ATTR, endpointId);
                    context.setAttribute("messageId", jmsMessage.getJMSMessageID());
                    context.setAttribute("messageClass", messageClass.getSimpleName());

                    String json = extractMessageText(jmsMessage, endpointId);
                    logger.debug("Message JSON in endpoint {}: {}", endpointId, json);
                    T message = objectMapper.readValue(json, messageClass);
                    listenerMessageProcessor.processMessage(message);
                } catch (JmsException | JMSException | IOException e) {
                    // Retryable - network, broker issues
                    throw new MessagingException("Message processing failed in endpoint: " + endpointId, e);
                } catch (IllegalArgumentException e) {
                    // Non-retryable - bad message format, validation
                    logger.error("Invalid message in endpoint '{}', will not retry: {}", endpointId, e.getMessage());
                    throw e; // Don't wrap, don't retry
                } catch (Exception e) {
                    logger.error("Unexpected error in endpoint '{}'", endpointId, e);
                }

                return null;
            });
        });

        return endpoint;
    }

    private String extractMessageText(jakarta.jms.Message jmsMessage, String endpointId) throws JMSException {
        if (!(jmsMessage instanceof TextMessage textMessage)) {
            throw new IllegalArgumentException("Expected TextMessage in endpoint '" + endpointId +
                "' but got: " + (jmsMessage != null ? jmsMessage.getClass().getName() : "null"));
        }
        String text = textMessage.getText();
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Received empty message body in endpoint '" + endpointId + "'");
        }
        return text;
    }
}
