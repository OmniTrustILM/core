package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.actions.ActionsJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.auditlogs.AuditLogsJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.event.EventJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.notification.NotificationJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.scheduler.SchedulerJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.validation.ValidationJmsEndpointConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for all standard JMS endpoint configs.
 *
 * <p>Verifies that each config correctly maps MessagingProperties (queue names, routing keys)
 * to {@link SimpleJmsListenerEndpoint} fields for both RabbitMQ and Azure Service Bus.</p>
 *
 * <p>For RabbitMQ: destination = /queues/{name}, no subscription, no selector (broker handles routing via bindings).<br>
 * For ServiceBus: destination = topic (exchange), subscription = queue name, selector = "routingKey = '{rk}'".</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JmsEndpointConfigTest {

    private static final String EXCHANGE = "czertainly";

    @Mock
    private MessagingProperties messagingProperties;

    @Mock
    private RetryTemplate retryTemplate;

    private MessagingProperties.Queue queue;
    private MessagingProperties.RoutingKey routingKey;
    private MessagingConcurrencyProperties concurrencyProperties;

    @BeforeEach
    void setUpSharedMocks() {
        queue = new MessagingProperties.Queue(
                "core.actions", "core.audit-logs", "core.events",
                "core.notifications", "core.scheduler", "core.validation"
        );
        routingKey = new MessagingProperties.RoutingKey(
                "action", "audit-logs", "event",
                "notification", "scheduler", "validation"
        );
        concurrencyProperties = new MessagingConcurrencyProperties("10", "5", "5", "3", "10", "5");

        when(messagingProperties.queue()).thenReturn(queue);
        when(messagingProperties.routingKey()).thenReturn(routingKey);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void givenRabbitMQ(String queueName) {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);
        when(messagingProperties.consumerDestination(queueName)).thenReturn("/queues/" + queueName);
    }

    private void givenServiceBus(String queueName) {
        when(messagingProperties.brokerType()).thenReturn(MessagingProperties.BrokerType.SERVICEBUS);
        when(messagingProperties.consumerDestination(queueName)).thenReturn(EXCHANGE);
    }

    private void assertRabbitMQ(SimpleJmsListenerEndpoint endpoint, String queueName) {
        assertThat(endpoint.getDestination()).isEqualTo("/queues/" + queueName);
        assertThat(endpoint.getSubscription()).isNull();
        assertThat(endpoint.getSelector()).isNull();
    }

    private void assertServiceBus(SimpleJmsListenerEndpoint endpoint, String queueName, String rk) {
        assertThat(endpoint.getDestination()).isEqualTo(EXCHANGE);
        assertThat(endpoint.getSubscription()).isEqualTo(queueName);
        assertThat(endpoint.getSelector()).isEqualTo("routingKey = '" + rk + "'");
    }

    @SuppressWarnings("unchecked")
    private <T> MessageProcessor<T> mockProcessor() {
        return mock(MessageProcessor.class);
    }

    // -------------------------------------------------------------------------
    // ActionsJmsEndpointConfig
    // -------------------------------------------------------------------------

    @Nested
    class ActionsEndpointConfigTests {

        private ActionsJmsEndpointConfig config;

        @BeforeEach
        void setUp() {
            config = new ActionsJmsEndpointConfig(
                    new ObjectMapper(), mockProcessor(), retryTemplate, messagingProperties, concurrencyProperties);
        }

        @Test
        void rabbitMQ_setsQueueDestination_noSubscriptionOrSelector() {
            givenRabbitMQ("core.actions");
            assertRabbitMQ(config.listenerEndpoint(), "core.actions");
        }

        @Test
        void serviceBus_setsTopicDestination_subscriptionAndSelector() {
            givenServiceBus("core.actions");
            assertServiceBus(config.listenerEndpoint(), "core.actions", "action");
        }
    }

    // -------------------------------------------------------------------------
    // AuditLogsJmsEndpointConfig
    // -------------------------------------------------------------------------

    @Nested
    class AuditLogsEndpointConfigTests {

        private AuditLogsJmsEndpointConfig config;

        @BeforeEach
        void setUp() {
            config = new AuditLogsJmsEndpointConfig(
                    new ObjectMapper(), mockProcessor(), retryTemplate, messagingProperties, concurrencyProperties);
        }

        @Test
        void rabbitMQ_setsQueueDestination_noSubscriptionOrSelector() {
            givenRabbitMQ("core.audit-logs");
            assertRabbitMQ(config.listenerEndpoint(), "core.audit-logs");
        }

        @Test
        void serviceBus_setsTopicDestination_subscriptionAndSelector() {
            givenServiceBus("core.audit-logs");
            assertServiceBus(config.listenerEndpoint(), "core.audit-logs", "audit-logs");
        }
    }

    // -------------------------------------------------------------------------
    // EventJmsEndpointConfig
    // -------------------------------------------------------------------------

    @Nested
    class EventEndpointConfigTests {

        private EventJmsEndpointConfig config;

        @BeforeEach
        void setUp() {
            config = new EventJmsEndpointConfig(
                    new ObjectMapper(), mockProcessor(), retryTemplate, messagingProperties, concurrencyProperties);
        }

        @Test
        void rabbitMQ_setsQueueDestination_noSubscriptionOrSelector() {
            givenRabbitMQ("core.events");
            assertRabbitMQ(config.listenerEndpoint(), "core.events");
        }

        @Test
        void serviceBus_setsTopicDestination_subscriptionAndSelector() {
            givenServiceBus("core.events");
            assertServiceBus(config.listenerEndpoint(), "core.events", "event");
        }
    }

    // -------------------------------------------------------------------------
    // NotificationJmsEndpointConfig
    // -------------------------------------------------------------------------

    @Nested
    class NotificationEndpointConfigTests {

        private NotificationJmsEndpointConfig config;

        @BeforeEach
        void setUp() {
            config = new NotificationJmsEndpointConfig(
                    new ObjectMapper(), mockProcessor(), retryTemplate, messagingProperties, concurrencyProperties);
        }

        @Test
        void rabbitMQ_setsQueueDestination_noSubscriptionOrSelector() {
            givenRabbitMQ("core.notifications");
            assertRabbitMQ(config.listenerEndpoint(), "core.notifications");
        }

        @Test
        void serviceBus_setsTopicDestination_subscriptionAndSelector() {
            givenServiceBus("core.notifications");
            assertServiceBus(config.listenerEndpoint(), "core.notifications", "notification");
        }
    }

    // -------------------------------------------------------------------------
    // SchedulerJmsEndpointConfig
    // -------------------------------------------------------------------------

    @Nested
    class SchedulerEndpointConfigTests {

        private SchedulerJmsEndpointConfig config;

        @BeforeEach
        void setUp() {
            config = new SchedulerJmsEndpointConfig(
                    new ObjectMapper(), mockProcessor(), retryTemplate, messagingProperties, concurrencyProperties);
        }

        @Test
        void rabbitMQ_setsQueueDestination_noSubscriptionOrSelector() {
            givenRabbitMQ("core.scheduler");
            assertRabbitMQ(config.listenerEndpoint(), "core.scheduler");
        }

        @Test
        void serviceBus_setsTopicDestination_subscriptionAndSelector() {
            givenServiceBus("core.scheduler");
            assertServiceBus(config.listenerEndpoint(), "core.scheduler", "scheduler");
        }
    }

    // -------------------------------------------------------------------------
    // ValidationJmsEndpointConfig
    // -------------------------------------------------------------------------

    @Nested
    class ValidationEndpointConfigTests {

        private ValidationJmsEndpointConfig config;

        @BeforeEach
        void setUp() {
            config = new ValidationJmsEndpointConfig(
                    new ObjectMapper(), mockProcessor(), retryTemplate, messagingProperties, concurrencyProperties);
        }

        @Test
        void rabbitMQ_setsQueueDestination_noSubscriptionOrSelector() {
            givenRabbitMQ("core.validation");
            assertRabbitMQ(config.listenerEndpoint(), "core.validation");
        }

        @Test
        void serviceBus_setsTopicDestination_subscriptionAndSelector() {
            givenServiceBus("core.validation");
            assertServiceBus(config.listenerEndpoint(), "core.validation", "validation");
        }
    }
}
