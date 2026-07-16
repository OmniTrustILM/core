package com.otilm.core.util.mockbeans;

import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.Mockito.mock;

/**
 * Mocks the JMS producers (external-boundary I/O that tests never exercise for real).
 */
@TestConfiguration
public class ProducerMocks {

    @Bean
    @Primary
    NotificationProducer mockNotificationProducer() {
        return mock(NotificationProducer.class);
    }

    @Bean
    @Primary
    ActionProducer mockActionProducer() {
        return mock(ActionProducer.class);
    }

    @Bean
    @Primary
    EventProducer mockEventProducer() {
        return mock(EventProducer.class);
    }

    @Bean
    @Primary
    ValidationProducer mockValidationProducer() {
        return mock(ValidationProducer.class);
    }
}
