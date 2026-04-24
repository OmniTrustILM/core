package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.repository.ProxyRepository;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;

/**
 * Handler for health check messages from proxy instances.
 *
 * <p>Health check messages are fire-and-forget style messages that indicate
 * a proxy instance is alive and connected. This handler updates the proxy
 * status and last activity timestamp in the database.</p>
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class HealthCheckHandler implements MessageTypeResponseHandler {

    private static final String MESSAGE_TYPE = "health.*";

    private final ProxyRepository proxyRepository;

    public HealthCheckHandler(ProxyRepository proxyRepository) {
        this.proxyRepository = proxyRepository;
    }

    @Override
    public String getMessageType() {
        return MESSAGE_TYPE;
    }

    @Override
    @Transactional
    public void handleResponse(ProxyMessage message) {
        String proxyCode = message.getProxyId();
        if (proxyCode == null || proxyCode.isBlank()) {
            log.warn("Ignoring health check with missing proxyId; timestamp={}", message.getTimestamp());
            return;
        }
        log.info("Health check received from proxy: proxyCode={} timestamp={}",
                proxyCode, message.getTimestamp());

        proxyRepository.findByCode(proxyCode).ifPresentOrElse(
            proxy -> {
                proxy.setStatus(ProxyStatus.CONNECTED);
                proxy.setLastActivity(OffsetDateTime.now());
                proxyRepository.save(proxy);
                log.debug("Updated proxy status: code={} status=CONNECTED", proxyCode);
            },
            () -> log.warn("Received health check from unknown proxy: code={}", proxyCode)
        );
    }
}
