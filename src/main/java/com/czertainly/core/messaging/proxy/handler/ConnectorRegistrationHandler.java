package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ConnectorRegistrationRequest;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.model.client.connector.ConnectorRequestDto;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.core.service.ConnectorRegistrationService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Handler for connector registration messages from proxy instances.
 *
 * <p>Registration messages are fire-and-forget: the proxy sends the request
 * and does not wait for a response. This handler converts the message to
 * a ConnectorRequestDto and delegates to ConnectorRegistrationService.</p>
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class ConnectorRegistrationHandler implements MessageTypeResponseHandler {

    private static final String MESSAGE_TYPE = "connector.register";

    private final ConnectorRegistrationService connectorRegistrationService;

    public ConnectorRegistrationHandler(ConnectorRegistrationService connectorRegistrationService) {
        this.connectorRegistrationService = connectorRegistrationService;
    }

    @Override
    public String getMessageType() {
        return MESSAGE_TYPE;
    }

    @Override
    @Transactional
    public void handleResponse(ProxyMessage message) {
        ConnectorRegistrationRequest regReq = message.getConnectorRegistrationRequest();
        if (regReq == null) {
            log.warn("Received connector registration message with no registration data: proxyId={}",
                    message.getProxyId());
            return;
        }

        log.info("Processing connector registration from proxy: name={} url={} proxyCode={}",
                regReq.getName(), regReq.getUrl(), regReq.getProxyCode());

        try {
            ConnectorRequestDto dto = toConnectorRequestDto(regReq);
            var result = connectorRegistrationService.registerConnector(dto);
            log.info("Connector registered successfully: name={} uuid={}",
                    regReq.getName(), result.getUuid());
        } catch (Exception e) {
            log.error("Failed to register connector: name={} error={}",
                    regReq.getName(), e.getMessage(), e);
        }
    }

    private ConnectorRequestDto toConnectorRequestDto(ConnectorRegistrationRequest regReq) {
        ConnectorRequestDto dto = new ConnectorRequestDto();
        dto.setName(regReq.getName());
        dto.setUrl(regReq.getUrl());
        dto.setAuthType(AuthType.findByCode(regReq.getAuthType()));
        dto.setProxyCode(regReq.getProxyCode());
        return dto;
    }
}
