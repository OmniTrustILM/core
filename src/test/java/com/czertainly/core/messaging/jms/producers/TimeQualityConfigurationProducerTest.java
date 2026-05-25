package com.czertainly.core.messaging.jms.producers;

import com.czertainly.api.model.messaging.timequality.TimeQualityConfigSnapshot;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.retry.support.RetryTemplate;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimeQualityConfigurationProducerTest {

    @Mock JmsTemplate jmsTemplate;
    @Mock MessagingProperties messagingProperties;

    private TimeQualityConfigurationProducer producer;

    @BeforeEach
    void setUp() {
        when(messagingProperties.produceDestinationTimeQualityConfig()).thenReturn("/exchanges/czertainly/time-quality.config");
        producer = new TimeQualityConfigurationProducer(jmsTemplate, messagingProperties, RetryTemplate.defaultInstance());
    }

    @Test
    void publishSnapshot_sendsMessageWithAllConfigurations() {
        TimeQualityConfiguration config = buildConfig("profile-a");

        producer.publishSnapshot(List.of(config), null);

        ArgumentCaptor<Object> messageCaptor = ArgumentCaptor.forClass(Object.class);
        verify(jmsTemplate).convertAndSend(
                eq("/exchanges/czertainly/time-quality.config"),
                messageCaptor.capture(),
                any(MessagePostProcessor.class));

        TimeQualityConfigSnapshot sent = (TimeQualityConfigSnapshot) messageCaptor.getValue();
        assertThat(sent.getConfigurations()).hasSize(1);
        assertThat(sent.getConfigurations().get(0).getId()).isEqualTo(config.getUuid());
        assertThat(sent.getGeneratedAt()).isNotNull();
        assertThat(sent.getCorrelationId()).isNull();
    }

    @Test
    void publishSnapshot_withEmptyList_sendsEmptySnapshot() {
        producer.publishSnapshot(List.of(), null);

        ArgumentCaptor<Object> messageCaptor = ArgumentCaptor.forClass(Object.class);
        verify(jmsTemplate).convertAndSend(anyString(), messageCaptor.capture(), any(MessagePostProcessor.class));

        TimeQualityConfigSnapshot sent = (TimeQualityConfigSnapshot) messageCaptor.getValue();
        assertThat(sent.getConfigurations()).isEmpty();
    }

    private TimeQualityConfiguration buildConfig(String name) {
        TimeQualityConfiguration c = new TimeQualityConfiguration();
        c.setName(name);
        c.setNtpServers(List.of("pool.ntp.org"));
        c.setNtpCheckInterval(Duration.ofSeconds(30));
        c.setNtpSamplesPerServer(4);
        c.setNtpCheckTimeout(Duration.ofSeconds(5));
        c.setNtpServersMinReachable(1);
        c.setMaxClockDrift(Duration.ofSeconds(1));
        c.setLeapSecondGuard(false);
        return c;
    }
}
