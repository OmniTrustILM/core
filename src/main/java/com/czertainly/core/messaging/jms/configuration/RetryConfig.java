package com.czertainly.core.messaging.jms.configuration;

import jakarta.jms.JMSException;
import org.messaginghub.pooled.jms.JmsPoolConnectionFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jms.JmsException;
import org.springframework.retry.RetryPolicy;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.retry.backoff.ExponentialBackOffPolicy;
import org.springframework.retry.policy.NeverRetryPolicy;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableRetry
public class RetryConfig {

    /**
     * Retry template for JMS listeners — logging only, no pool interaction.
     * Listener containers use the raw {@code ConnectionFactory} bean, not the pooled one.
     */
    @Bean
    public RetryTemplate jmsRetryTemplate(MessagingProperties messagingProperties) {
        RetryTemplate template = createRetryTemplate(messagingProperties);
        template.registerListener(new JmsRetryListener());
        return template;
    }

    /**
     * Retry template for JMS producers — clears the producer connection pool on
     * connection-level failures to force a fresh connection on the next retry.
     */
    @Bean
    public RetryTemplate producerRetryTemplate(MessagingProperties messagingProperties,
                                                JmsPoolConnectionFactory producerConnectionFactory) {
        RetryTemplate template = createRetryTemplate(messagingProperties);
        template.registerListener(new ProducerRetryListener(producerConnectionFactory));
        return template;
    }

    private RetryTemplate createRetryTemplate(MessagingProperties messagingProperties) {
        RetryTemplate template = new RetryTemplate();

        if (messagingProperties.producer() != null && messagingProperties.producer().retry() != null &&
                messagingProperties.producer().retry().enabled()) {

            Map<Class<? extends Throwable>, Boolean> retryableExceptions = new HashMap<>();
            retryableExceptions.put(JmsException.class, true);    // Spring JMS wrapper
            retryableExceptions.put(JMSException.class, true);    // raw jakarta.jms (e.g. getJMSMessageID())
            retryableExceptions.put(IOException.class, true);     // network / deserialization

            SimpleRetryPolicy retryPolicy = new SimpleRetryPolicy(
                    messagingProperties.producer().retry().maxAttempts(),
                    retryableExceptions, true
            );
            template.setRetryPolicy(retryPolicy);

            ExponentialBackOffPolicy backoff = new ExponentialBackOffPolicy();
            backoff.setInitialInterval(messagingProperties.producer().retry().initialInterval());
            backoff.setMultiplier(messagingProperties.producer().retry().multiplier());
            backoff.setMaxInterval(messagingProperties.producer().retry().maxInterval());
            template.setBackOffPolicy(backoff);
        } else {
            RetryPolicy neverRetryPolicy = new NeverRetryPolicy();
            template.setRetryPolicy(neverRetryPolicy);
        }

        return template;
    }

}
