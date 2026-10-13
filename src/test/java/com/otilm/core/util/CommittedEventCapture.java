package com.otilm.core.util;

import com.otilm.core.messaging.model.EventMessage;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.PayloadApplicationEvent;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Captures application event messages only when their publishing transaction commits. */
public final class CommittedEventCapture implements ApplicationListener<PayloadApplicationEvent<?>>, AutoCloseable {
    private final ConfigurableApplicationContext context;
    private final List<EventMessage> messages = new CopyOnWriteArrayList<>();

    public CommittedEventCapture(ConfigurableApplicationContext context) {
        this.context = context;
        context.addApplicationListener(this);
    }

    @Override
    public void onApplicationEvent(PayloadApplicationEvent<?> event) {
        if (event.getPayload() instanceof EventMessage message) {
            if (TransactionSynchronizationManager.isActualTransactionActive()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        messages.add(message);
                    }
                });
            } else {
                messages.add(message);
            }
        }
    }

    public List<EventMessage> messages(String eventCode) {
        return messages.stream().filter(message -> message.getEvent().getCode().equals(eventCode)).toList();
    }

    @Override
    public void close() {
        context.removeApplicationListener(this);
    }
}
