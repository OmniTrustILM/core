package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.exception.MessageHandlingException;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Listener for the per-instance proxy response queue.
 * Handles only request-reply correlation -- matches responses to pending
 * CompletableFutures by correlation ID.
 */
@Slf4j
@Component("instanceProxyMessageListener")
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class InstanceProxyMessageListener implements MessageProcessor<ProxyMessage> {

    private final ProxyMessageCorrelator correlator;

    public InstanceProxyMessageListener(ProxyMessageCorrelator correlator) {
        this.correlator = correlator;
        log.info("InstanceProxyMessageListener initialized");
    }

    @Override
    public void processMessage(ProxyMessage message) throws MessageHandlingException {
        if (message == null) {
            log.warn("Received null proxy message on instance queue, ignoring");
            return;
        }

        String correlationId = message.getCorrelationId();
        if (correlationId == null || correlationId.isBlank()) {
            log.warn("Received message on instance queue without correlationId, discarding");
            return;
        }

        if (!correlator.tryCompleteRequest(message)) {
            log.warn("No pending request for correlationId={} on instance queue", correlationId);
        }
    }
}
