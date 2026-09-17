package com.otilm.core.messaging.jms.producers;

import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.EventMessage;
import java.util.Objects;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.lang.NonNull;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@AllArgsConstructor
public class EventProducer {

    private static final Logger logger = LoggerFactory.getLogger(EventProducer.class);

    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    /**
     * Releases an event only if the transaction that raised it commits, for a publisher that raises one while holding
     * the row it describes — a rolled-back ending must not announce itself. {@code fallbackExecution} keeps a publisher
     * outside any transaction working, where the send happens inline.
     *
     * <p>
     * A dispatch failure is logged, not rethrown: Spring hands what an {@code AFTER_COMMIT} synchronization throws to
     * whoever called commit, which would report committed work as failed.
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onEventMessage(EventMessage eventMessage) {
        try {
            produceMessage(eventMessage);
        } catch (Exception e) {
            logger
                    .error("Could not dispatch event {} for {} {}: {}", eventMessage.getEvent(),
                            eventMessage.getResource(), eventMessage.getObjectUuid(), e.getMessage(), e);
        }
    }

    public void produceMessage(@NonNull final EventMessage eventMessage) {
        Objects.requireNonNull(eventMessage, "Event message cannot be null");

        producerRetryTemplate.execute(context -> {
            jmsTemplate.convertAndSend(messagingProperties.produceDestinationEvent(), eventMessage, message -> {
                message.setJMSType(messagingProperties.routingKey().event());
                return message;
            });
            return null;
        });
    }
}
