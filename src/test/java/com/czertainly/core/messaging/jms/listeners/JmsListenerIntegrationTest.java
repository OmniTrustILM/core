package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.util.BaseMessagingIntTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

/**
 * Integration test verifying end-to-end message delivery via RabbitMQ testcontainer.
 *
 * <p>Verifies that the JMS listener endpoint configuration ({@code EventJmsEndpointConfig})
 * correctly routes messages from the RabbitMQ exchange to the queue and that
 * {@link EventListener} receives and processes the deserialized message.</p>
 *
 * <p>Flow: EventProducer → /exchanges/czertainly/event → [RabbitMQ binding] →
 * /queues/core.events → EventJmsEndpointConfig listener → EventListener.processMessage()</p>
 *
 * <p>{@code inheritProfiles = false} is required: {@code BaseSpringBootTest} adds the {@code "test"}
 * profile which Spring merges with all subclass profiles. With {@code "test"} active,
 * {@code @Profile("!test")} beans (listener endpoint configs, {@code JmsListenersConfigurerImpl})
 * are excluded and listener containers never start.</p>
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class JmsListenerIntegrationTest extends BaseMessagingIntTest {

    @Autowired
    private EventProducer eventProducer;

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

        EventMessage sentMessage = new EventMessage(
                ResourceEvent.CERTIFICATE_DISCOVERED,
                Resource.DISCOVERY,
                UUID.randomUUID(),
                "integration-test-payload"
        );

        eventProducer.produceMessage(sentMessage);

        boolean received = latch.await(2, TimeUnit.SECONDS);
        assertThat(received)
                .as("EventListener should receive the message within 5 seconds")
                .isTrue();

        verify(eventListener).processMessage(any(EventMessage.class));
    }
}
