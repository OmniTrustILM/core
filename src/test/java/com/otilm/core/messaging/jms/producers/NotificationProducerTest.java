package com.otilm.core.messaging.jms.producers;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.NotificationMessage;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.retry.support.RetryTemplate;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class NotificationProducerTest {

    @Mock
    JmsTemplate jmsTemplate;
    @Mock
    MessagingProperties messagingProperties;

    private NotificationProducer producer;

    @BeforeEach
    void setUp() {
        lenient().when(messagingProperties.produceDestinationNotifications()).thenReturn("/exchanges/ilm/notification");

        MessagingProperties.RoutingKey routingKey = new MessagingProperties.RoutingKey("actions", "audit-logs", "event",
                "notification", "scheduler", "validation", "time-quality.config-request", "time-quality.config",
                "time-quality.results", "provider.status-poll", "provider.discovery-work");
        lenient().when(messagingProperties.routingKey()).thenReturn(routingKey);

        producer = new NotificationProducer(jmsTemplate, messagingProperties,
                RetryTemplate.builder().maxAttempts(1).build());
    }

    private NotificationMessage message() {
        return new NotificationMessage(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, UUID.randomUUID(),
                List.of(UUID.randomUUID()), null, null, UUID.randomUUID(), UUID.randomUUID());
    }

    private void makeDispatchFail() {
        doThrow(new IllegalStateException("broker unreachable"))
                .when(jmsTemplate)
                .convertAndSend(anyString(), any(Object.class), any(MessagePostProcessor.class));
    }

    /**
     * The listener runs after the transaction has committed, and Spring propagates what it throws to whoever called
     * commit -- which would report committed work as failed. Nothing may escape.
     */
    @Test
    void aDispatchFailureDoesNotEscapeTheAfterCommitListener() {
        makeDispatchFail();

        assertThatCode(() -> producer.onNotificationMessage(message())).doesNotThrowAnyException();
    }

    /**
     * The guard belongs to the listener alone: a caller that dispatches directly is still inside its own operation and
     * can act on the failure.
     */
    @Test
    void aDirectDispatchStillReportsTheFailure() {
        makeDispatchFail();
        NotificationMessage message = message();

        assertThatThrownBy(() -> producer.produceMessage(message))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("broker unreachable");
    }

    @Test
    void aMessageWithNoRecipientIsNotDispatched() {
        NotificationMessage withoutRecipients = new NotificationMessage(ResourceEvent.CERTIFICATE_DISCOVERED,
                Resource.CERTIFICATE, UUID.randomUUID(), List.of(), null, null, null, null);

        assertThatCode(() -> producer.produceMessage(withoutRecipients)).doesNotThrowAnyException();
    }
}
