package com.otilm.core.messaging.jms.producers;

import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.retry.support.RetryTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkProducerTest {

    @Mock
    JmsTemplate jmsTemplate;
    @Mock
    MessagingProperties messagingProperties;

    private DiscoveryWorkProducer producer;

    @BeforeEach
    void setUp() {
        when(messagingProperties.produceDestinationProviderDiscoveryWork())
                .thenReturn("/exchanges/ilm/provider.discovery-work");

        MessagingProperties.RoutingKey routingKey = new MessagingProperties.RoutingKey("actions", "audit-logs", "event",
                "notification", "scheduler", "validation", "time-quality.config-request", "time-quality.config",
                "time-quality.results", "provider.status-poll", "provider.discovery-work");
        lenient().when(messagingProperties.routingKey()).thenReturn(routingKey);

        producer = new DiscoveryWorkProducer(jmsTemplate, messagingProperties, RetryTemplate.defaultInstance());
    }

    @Test
    void produceMessage_invokesJmsTemplate() {
        DiscoveryWorkMessage msg = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.STATUS, 1);

        producer.produceMessage(msg);

        ArgumentCaptor<Object> messageCaptor = ArgumentCaptor.forClass(Object.class);
        verify(jmsTemplate)
                .convertAndSend(eq("/exchanges/ilm/provider.discovery-work"), messageCaptor.capture(),
                        any(MessagePostProcessor.class));

        DiscoveryWorkMessage sent = (DiscoveryWorkMessage) messageCaptor.getValue();
        assertThat(sent).isEqualTo(msg);
    }
}
