package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.exception.MessageHandlingException;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.messaging.proxy.handler.MessageTypeHandlerRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Listener for the shared proxy queue (fire-and-forget messages).
 * Dispatches messages by type to registered handlers (health checks,
 * connector registration). Does not perform correlation.
 */
@Slf4j
@Component("sharedProxyMessageListener")
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class SharedProxyMessageListener implements MessageProcessor<ProxyMessage> {

    private final MessageTypeHandlerRegistry handlerRegistry;

    public SharedProxyMessageListener(MessageTypeHandlerRegistry handlerRegistry) {
        this.handlerRegistry = handlerRegistry;
        log.info("SharedProxyMessageListener initialized");
    }

    @Override
    public void processMessage(ProxyMessage message) throws MessageHandlingException {
        if (message == null) {
            log.warn("Received null proxy message on shared queue, ignoring");
            return;
        }

        String messageType = message.getMessageType();
        if (messageType == null || messageType.isBlank()) {
            log.warn("Received message on shared queue without messageType, discarding");
            return;
        }

        if (!handlerRegistry.dispatch(message)) {
            log.warn("No handler for messageType={} on shared queue", messageType);
        }
    }
}
