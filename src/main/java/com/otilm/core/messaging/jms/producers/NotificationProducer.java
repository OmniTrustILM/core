package com.otilm.core.messaging.jms.producers;

import com.otilm.api.model.common.events.data.InternalNotificationEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
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
public class NotificationProducer {
    private static final Logger logger = LoggerFactory.getLogger(NotificationProducer.class);

    private final JmsTemplate jmsTemplate;
    private final MessagingProperties messagingProperties;
    private final RetryTemplate producerRetryTemplate;

    private void sendMessage(final NotificationMessage notificationMessage) {
        producerRetryTemplate.execute(context -> {
            jmsTemplate
                    .convertAndSend(messagingProperties.produceDestinationNotifications(), notificationMessage,
                            message -> {
                                message.setJMSType(messagingProperties.routingKey().notification());
                                return message;
                            });
            return null;
        });
    }

    /**
     * Spring propagates what an {@code AFTER_COMMIT} synchronization throws to whoever called commit, by which point
     * the transaction has committed -- so letting a dispatch failure out reports committed work as failed. Retries are
     * exhausted by here, so the log is all that is left. Not loss-free on the {@code fallbackExecution} path though:
     * with no transaction the listener runs inline, where the publisher could still have acted on the failure.
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onNotificationMessage(NotificationMessage notificationMessage) {
        try {
            produceMessage(notificationMessage);
        } catch (Exception e) {
            logger
                    .error("Could not dispatch the notification for event {} on {} {}: {}",
                            notificationMessage.getEvent(), notificationMessage.getResource(),
                            notificationMessage.getObjectUuid(), e.getMessage(), e);
        }
    }

    public void produceMessage(@NonNull final NotificationMessage notificationMessage) {
        Objects.requireNonNull(notificationMessage, "Notification message cannot be null");
        if ((notificationMessage.getNotificationProfileUuids() == null
                || notificationMessage.getNotificationProfileUuids().isEmpty())
                && (notificationMessage.getRecipients() == null || notificationMessage.getRecipients().isEmpty())) {
            logger
                    .warn("Recipients for notification of event {} (resource {} {}) are empty; not sending.",
                            notificationMessage.getEvent().getLabel(), notificationMessage.getResource(),
                            notificationMessage.getObjectUuid());
        } else {
            sendMessage(notificationMessage);
        }
    }

    public void produceInternalNotificationMessage(Resource resource, UUID resourceUUID,
            List<NotificationRecipient> recipients, String text, String detail) {
        produceMessage(new NotificationMessage(null, resource, resourceUUID, null, recipients,
                new InternalNotificationEventData(text, detail)));
    }
}
