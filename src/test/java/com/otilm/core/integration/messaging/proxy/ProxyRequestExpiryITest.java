package com.otilm.core.integration.messaging.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.clients.mq.model.ConnectorRequest;
import com.otilm.api.clients.mq.model.CoreMessage;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.proxy.CoreMessageProducer;
import com.otilm.core.messaging.proxy.ProxyProperties;
import com.otilm.core.util.BaseMessagingIntTest;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.support.converter.MessageConverter;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.test.context.ActiveProfiles;

import static org.awaitility.Awaitility.await;

/**
 * Proves on a real RabbitMQ broker that a proxy request expires with its time to live.
 *
 * <p>
 * The requests go to an exchange of their own, whose only queue has no consumer and dead-letters what expires to a
 * queue of its own: expiry is the only way a message leaves it, and Core's shared proxy listener never sees them.
 * </p>
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class ProxyRequestExpiryITest extends BaseMessagingIntTest {

    private static final String EXCHANGE = "ilm-proxy-expiry-test";
    private static final String QUEUE = "proxy-expiry-test";
    private static final String EXPIRED_QUEUE = "proxy-expiry-test.expired";
    private static final String PROXY_ID = "expiry-test";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private JmsTemplate jmsTemplate;

    @Autowired
    private MessagingProperties messagingProperties;

    @Autowired
    private RetryTemplate producerRetryTemplate;

    @Autowired
    private MessageConverter messageConverter;

    @Test
    void aRequestPastItsTimeToLiveExpiresWhileALiveOneStays() {
        CoreMessageProducer producer = new CoreMessageProducer(jmsTemplate,
                new ProxyProperties(EXCHANGE, "core", "test-instance", null, null, null), messagingProperties,
                producerRetryTemplate, messageConverter);

        // Sent first: RabbitMQ drops an expired message only once it reaches the head of the queue
        producer.send(request("expiring"), PROXY_ID, Duration.ofSeconds(1));
        producer.send(request("live"), PROXY_ID, Duration.ofMinutes(5));

        // Only a request that reached the queue can be dead-lettered from it
        await().atMost(Duration.ofSeconds(20)).until(() -> messagesIn(EXPIRED_QUEUE) == 1);
        await().during(Duration.ofSeconds(3)).atMost(Duration.ofSeconds(10)).until(() -> messagesIn(QUEUE) == 1);
    }

    private static CoreMessage request(String correlationId) {
        return CoreMessage
                .builder()
                .correlationId(correlationId)
                .messageType("POST.v1.test")
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

    private static long messagesIn(String queue) throws IOException, InterruptedException {
        String listing = rabbitMQContainer
                .execInContainer("rabbitmqctl", "list_queues", "--formatter", "json", "name", "messages")
                .getStdout();
        for (JsonNode entry : JSON.readTree(listing)) {
            if (queue.equals(entry.path("name").asText())) {
                return entry.path("messages").asLong();
            }
        }
        throw new IllegalStateException("Queue " + queue + " is not declared on the broker");
    }
}
