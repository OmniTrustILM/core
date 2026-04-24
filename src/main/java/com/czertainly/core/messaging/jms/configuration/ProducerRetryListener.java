package com.czertainly.core.messaging.jms.configuration;

import jakarta.jms.JMSException;
import org.messaginghub.pooled.jms.JmsPoolConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;

/**
 * Retry listener for JMS producer operations that clears the producer connection pool
 * on connection-level failures.
 *
 * <p>Backup workaround for a pooled-jms bug where {@code validateObject()} fails to detect
 * dead Qpid connections after {@code amqp:connection:forced}. Calling {@code pool.clear()}
 * between retries is an aggressive producer pool reset that forces {@code makeObject()} on
 * the next borrow to create a fresh connection.</p>
 *
 * <p>This listener is registered only on the producer retry template. Listener containers
 * use a separate {@code ConnectionFactory} and must never clear the producer pool.</p>
 *
 * @see RetryConfig#producerRetryTemplate(MessagingProperties, JmsPoolConnectionFactory)
 */
public class ProducerRetryListener implements RetryListener {
    private static final Logger logger = LoggerFactory.getLogger(ProducerRetryListener.class);

    private final JmsPoolConnectionFactory producerConnectionFactory;

    public ProducerRetryListener(JmsPoolConnectionFactory producerConnectionFactory) {
        this.producerConnectionFactory = producerConnectionFactory;
    }

    @Override
    public <T, E extends Throwable> boolean open(RetryContext context, RetryCallback<T, E> callback) {
        return true;
    }

    @Override
    public <T, E extends Throwable> void close(RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
        if (throwable != null) {
            logger.error("Producer send failed after {} attempts: {}",
                    context.getRetryCount(), throwable.getMessage(), throwable);
        }
    }

    @Override
    public <T, E extends Throwable> void onError(RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
        logger.warn("Producer retry attempt {} failed: {}",
                context.getRetryCount(), throwable.getMessage(), throwable);

        if (isConnectionFailure(throwable)) {
            logger.warn("Detected connection-level failure. Clearing producer connection pool "
                    + "to force fresh connection on next retry.");
            producerConnectionFactory.clear();
        }
    }

    private boolean isConnectionFailure(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof IllegalStateException) {
                return true;
            }
            if (current instanceof JMSException && current.getMessage() != null
                    && current.getMessage().contains("unrecoverable error")) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}