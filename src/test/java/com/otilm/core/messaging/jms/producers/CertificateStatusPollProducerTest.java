package com.otilm.core.messaging.jms.producers;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.handler.authority.CertificateOperation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.retry.support.RetryTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollProducerTest {

    @Mock JmsTemplate jmsTemplate;
    @Mock MessagingProperties messagingProperties;

    private CertificateStatusPollProducer producer;

    @BeforeEach
    void setUp() {
        when(messagingProperties.produceDestinationProviderStatusPoll()).thenReturn("/exchanges/czertainly/provider.status-poll");

        MessagingProperties.RoutingKey routingKey = new MessagingProperties.RoutingKey(
                "actions", "audit-logs", "event", "notification", "scheduler",
                "validation", "time-quality-config-request", "time-quality-config",
                "time-quality-results", "provider.status-poll"
        );
        lenient().when(messagingProperties.routingKey()).thenReturn(routingKey);

        producer = new CertificateStatusPollProducer(jmsTemplate, messagingProperties, RetryTemplate.defaultInstance());
    }

    @Test
    void produceMessage_invokesJmsTemplate() {
        CertificateStatusPollMessage msg = new CertificateStatusPollMessage(
                Resource.CERTIFICATE, UUID.randomUUID(), CertificateOperation.ISSUE, 1
        );

        producer.produceMessage(msg);

        ArgumentCaptor<Object> messageCaptor = ArgumentCaptor.forClass(Object.class);
        verify(jmsTemplate).convertAndSend(
                eq("/exchanges/czertainly/provider.status-poll"),
                messageCaptor.capture(),
                any(MessagePostProcessor.class)
        );

        CertificateStatusPollMessage sent = (CertificateStatusPollMessage) messageCaptor.getValue();
        assertThat(sent).isEqualTo(msg);
    }
}
