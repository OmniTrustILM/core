package com.czertainly.core.messaging.jms;

import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.listeners.timequality.TimeQualityConfigRequestListener;
import com.czertainly.core.messaging.jms.listeners.timequality.TimeQualityResultListener;
import com.czertainly.core.messaging.jms.producers.TimeQualityConfigurationProducer;
import com.czertainly.core.messaging.jms.producers.TimeQualityMonitorInitializer;
import com.czertainly.core.signing.tsa.timequality.TimeQualityRegister;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.retry.support.RetryTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies that the time-quality messaging beans are gated by {@code messaging.time-quality.enabled}.
 *
 * <p>Mock dependencies are registered via {@code withBean(...)} rather than a nested {@code @Configuration}
 * class: a scannable configuration on the test classpath would be picked up by other {@code @SpringBootTest}
 * contexts and its mock {@code timeQualityConfigurationRepository} bean would collide with the real Spring
 * Data JPA repository.
 */
class TimeQualityMessagingToggleTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(JmsTemplate.class, () -> mock(JmsTemplate.class))
            .withBean(MessagingProperties.class, () -> mock(MessagingProperties.class))
            .withBean(RetryTemplate.class, () -> mock(RetryTemplate.class))
            .withBean(TimeQualityConfigurationRepository.class, () -> mock(TimeQualityConfigurationRepository.class))
            .withBean(TimeQualityRegister.class, () -> mock(TimeQualityRegister.class))
            .withUserConfiguration(
                    TimeQualityConfigurationProducer.class,
                    TimeQualityMonitorInitializer.class,
                    TimeQualityConfigRequestListener.class,
                    TimeQualityResultListener.class);

    @Test
    void beansAbsentWhenFlagUnset() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(TimeQualityConfigurationProducer.class);
            assertThat(context).doesNotHaveBean(TimeQualityMonitorInitializer.class);
            assertThat(context).doesNotHaveBean(TimeQualityConfigRequestListener.class);
            assertThat(context).doesNotHaveBean(TimeQualityResultListener.class);
        });
    }

    @Test
    void beansAbsentWhenFlagFalse() {
        runner.withPropertyValues("messaging.time-quality.enabled=false").run(context -> {
            assertThat(context).doesNotHaveBean(TimeQualityConfigurationProducer.class);
            assertThat(context).doesNotHaveBean(TimeQualityMonitorInitializer.class);
            assertThat(context).doesNotHaveBean(TimeQualityConfigRequestListener.class);
            assertThat(context).doesNotHaveBean(TimeQualityResultListener.class);
        });
    }

    @Test
    void beansPresentWhenFlagTrue() {
        runner.withPropertyValues("messaging.time-quality.enabled=true").run(context -> {
            assertThat(context).hasSingleBean(TimeQualityConfigurationProducer.class);
            assertThat(context).hasSingleBean(TimeQualityMonitorInitializer.class);
            assertThat(context).hasSingleBean(TimeQualityConfigRequestListener.class);
            assertThat(context).hasSingleBean(TimeQualityResultListener.class);
        });
    }
}
