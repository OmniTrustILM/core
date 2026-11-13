package com.otilm.core.util;

import com.otilm.api.exception.MessageHandlingException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.listeners.CertificateStatusPollListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Stands in for the broker consumers of a test that mocks the JMS producers with {@link ProducerMocks}: it delivers
 * what the platform queues to the real listeners, on the thread that queues it. An action reaches the
 * {@link ActionsListener} at once, and a failure of the listener stays with it, as a consumer never reports one to the
 * producer. The answers of an approval wait until the test delivers them, as the broker delivers them only once the
 * decision has committed. A status poll runs when the test asks for it.
 */
@Component
public class QueuedMessageDelivery {

    /** The schedule of a poll that a test runs, as the test context configures none. */
    private static final StatusPollProperties POLL_SCHEDULE = new StatusPollProperties(
            new StatusPollProperties.PollSchedule(List.of(Duration.ofSeconds(1)), 5), Map.of());

    private final ActionProducer actionProducer;
    private final ActionsListener actionsListener;
    private final CertificateStatusPollListener statusPollListener;
    private final StatusPollProperties statusPollProperties;
    private final List<ActionMessage> approvalAnswers = new ArrayList<>();
    private Authentication testAuthentication;

    public QueuedMessageDelivery(ActionProducer actionProducer, ActionsListener actionsListener,
            CertificateStatusPollListener statusPollListener, StatusPollProperties statusPollProperties) {
        this.actionProducer = actionProducer;
        this.actionsListener = actionsListener;
        this.statusPollListener = statusPollListener;
        this.statusPollProperties = statusPollProperties;
    }

    /**
     * Has the mocked {@link ActionProducer} deliver each message that it is given as {@link #deliver} does, for the
     * rest of the test, and forgets the answers that an earlier test left undelivered. The listener acts as the user
     * that each message names, so {@link #deliverApprovalAnswers()} authenticates the test again as the user that it is
     * authenticated as now.
     */
    public void deliverQueuedActions() {
        approvalAnswers.clear();
        testAuthentication = SecurityContextHolder.getContext().getAuthentication();
        Mockito.doAnswer(invocation -> {
            deliver(invocation.getArgument(0));
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    /**
     * Delivers a queued message as the broker consumer would: the answers of an approval wait for its decision, and a
     * failure of the listener is never reported to the producer.
     */
    public void deliver(ActionMessage message) {
        if (message.getApprovalUuid() != null) {
            approvalAnswers.add(message);
            return;
        }
        try {
            actionsListener.processMessage(message);
        } catch (MessageHandlingException e) {
            // the listener has failed the certificate and logged why
        }
    }

    /**
     * Delivers the answers of the approvals decided since, as the broker does once a decision has committed, and
     * authenticates the test again as the user that {@link #deliverQueuedActions()} found, as the listener acts as the
     * user that each answer names.
     */
    public void deliverApprovalAnswers() throws MessageHandlingException {
        for (ActionMessage answer : approvalAnswers) {
            actionsListener.processMessage(answer);
        }
        approvalAnswers.clear();
        SecurityContextHolder.getContext().setAuthentication(testAuthentication);
    }

    /**
     * Runs the status poll of the operation on the certificate that the platform schedules once the authority has
     * accepted the operation, and gives the listener its own schedule back afterwards.
     */
    public void pollStatus(UUID certificateUuid, CertificateOperation operation) throws MessageHandlingException {
        statusPollListener.setStatusPollProperties(POLL_SCHEDULE);
        try {
            statusPollListener
                    .processMessage(
                            new CertificateStatusPollMessage(Resource.CERTIFICATE, certificateUuid, operation, 0));
        } finally {
            statusPollListener.setStatusPollProperties(statusPollProperties);
        }
    }
}
