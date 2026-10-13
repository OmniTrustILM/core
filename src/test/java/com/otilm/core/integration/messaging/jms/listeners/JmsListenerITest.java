package com.otilm.core.integration.messaging.jms.listeners;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.messaging.jms.listeners.EventListener;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.util.BaseMessagingIntTest;
import jakarta.jms.JMSException;
import jakarta.jms.MessageListener;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jms.config.JmsListenerEndpointRegistry;
import org.springframework.jms.listener.DefaultMessageListenerContainer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

/**
 * Integration test verifying end-to-end message delivery via RabbitMQ testcontainer.
 *
 * <p>
 * Verifies that the JMS listener endpoint configuration ({@code EventJmsEndpointConfig}) correctly routes messages from
 * the RabbitMQ exchange to the queue and that {@link EventListener} receives and processes the deserialized message.
 * </p>
 *
 * <p>
 * Flow: EventProducer → /exchanges/ilm/event → [RabbitMQ binding] → /queues/core.events → EventJmsEndpointConfig
 * listener → EventListener.processMessage()
 * </p>
 *
 * <p>
 * {@code inheritProfiles = false} is required: {@code BaseSpringBootTest} adds the {@code "test"} profile which Spring
 * merges with all subclass profiles. With {@code "test"} active, {@code @Profile("!test")} beans (listener endpoint
 * configs, {@code JmsListenersConfigurerImpl}) are excluded and listener containers never start.
 * </p>
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class JmsListenerITest extends BaseMessagingIntTest {

    @Autowired
    private EventProducer eventProducer;

    @Autowired
    private JmsListenerEndpointRegistry endpointRegistry;

    // @MockitoBean (not @MockitoSpyBean) is intentional: EventListener is @Transactional, so Spring
    // wraps it in an AOP proxy. A spy wraps the underlying bean but the AOP proxy (injected into
    // EventJmsEndpointConfig.listenerMessageProcessor) bypasses the spy. @MockitoBean replaces the
    // bean entirely — no AOP proxy — so doAnswer intercepts the call directly.
    @MockitoBean
    private EventListener eventListener;

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void eventMessage_isDeliveredToEventListener() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);

        doAnswer(invocation -> {
            latch.countDown();
            return null;
        }).when(eventListener).processMessage(any(EventMessage.class));

        EventMessage sentMessage = new EventMessage(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.DISCOVERY,
                UUID.randomUUID(), "integration-test-payload");

        eventProducer.produceMessage(sentMessage);

        boolean received = latch.await(2, TimeUnit.SECONDS);
        assertThat(received).as("EventListener should receive the message within 5 seconds").isTrue();

        verify(eventListener).processMessage(any(EventMessage.class));
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void exhaustedDatabaseRetryIsRedeliveredByRabbitMq() throws Exception {
        DefaultMessageListenerContainer container = (DefaultMessageListenerContainer) endpointRegistry
                .getListenerContainer("eventListener");
        MessageListener original = (MessageListener) container.getMessageListener();
        CountDownLatch handled = new CountDownLatch(1);
        AtomicBoolean redelivered = new AtomicBoolean();
        AtomicInteger attempts = new AtomicInteger();
        List<Boolean> deliveries = new CopyOnWriteArrayList<>();
        UUID objectUuid = UUID.randomUUID();
        doAnswer(invocation -> {
            EventMessage message = invocation.getArgument(0);
            if (!objectUuid.equals(message.getObjectUuid())) {
                return null;
            }
            attempts.incrementAndGet();
            if (!redelivered.get()) {
                throw new DataAccessResourceFailureException("Database unavailable on the first delivery");
            }
            handled.countDown();
            return null;
        }).when(eventListener).processMessage(any(EventMessage.class));
        container.setMessageListener((MessageListener) message -> {
            try {
                boolean isRedelivery = message.getJMSRedelivered();
                redelivered.set(isRedelivery);
                deliveries.add(isRedelivery);
            } catch (JMSException e) {
                throw new IllegalStateException(e);
            }
            original.onMessage(message);
        });
        try {
            eventProducer.produceMessage(new EventMessage(ResourceEvent.CBOM_SYNCED, Resource.CBOM, objectUuid, null));

            assertThat(handled.await(25, TimeUnit.SECONDS))
                    .as("RabbitMQ must redeliver after the first delivery exhausts its retries")
                    .isTrue();
            assertThat(deliveries).containsExactly(false, true);
            assertThat(attempts).hasValue(4);
        } finally {
            container.setMessageListener(original);
        }
    }

}
