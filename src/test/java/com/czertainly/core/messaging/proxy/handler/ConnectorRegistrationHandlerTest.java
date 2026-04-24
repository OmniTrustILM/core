package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ConnectorRegistrationRequest;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.model.client.connector.ConnectorRequestDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.core.service.ConnectorRegistrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ConnectorRegistrationHandlerTest {

    @Mock
    private ConnectorRegistrationService connectorRegistrationService;

    private ConnectorRegistrationHandler handler;

    @BeforeEach
    void setUp() {
        handler = new ConnectorRegistrationHandler(connectorRegistrationService);
    }

    @Test
    void getMessageType_returnsConnectorRegister() {
        assertThat(handler.getMessageType()).isEqualTo("connector.register");
    }

    @Test
    void handleResponse_withValidRequest_callsRegisterConnector() throws Exception {
        UuidDto result = new UuidDto();
        result.setUuid("test-uuid-123");
        when(connectorRegistrationService.registerConnector(any())).thenReturn(result);

        ConnectorRegistrationRequest regReq = ConnectorRegistrationRequest.builder()
                .name("test-connector")
                .url("https://connector.example.com")
                .authType("none")
                .proxyCode("proxy-001")
                .build();

        ProxyMessage message = ProxyMessage.builder()
                .proxyId("proxy-001")
                .messageType("connector.register")
                .timestamp(Instant.now())
                .connectorRegistrationRequest(regReq)
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();

        ArgumentCaptor<ConnectorRequestDto> captor = ArgumentCaptor.forClass(ConnectorRequestDto.class);
        verify(connectorRegistrationService).registerConnector(captor.capture());

        ConnectorRequestDto captured = captor.getValue();
        assertThat(captured.getName()).isEqualTo("test-connector");
        assertThat(captured.getUrl()).isEqualTo("https://connector.example.com");
        assertThat(captured.getProxyCode()).isEqualTo("proxy-001");
    }

    @Test
    void handleResponse_withNullRegistrationRequest_handlesGracefully() throws Exception {
        ProxyMessage message = ProxyMessage.builder()
                .proxyId("proxy-001")
                .messageType("connector.register")
                .timestamp(Instant.now())
                .connectorRegistrationRequest(null)
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();
        verify(connectorRegistrationService, never()).registerConnector(any());
    }

    @Test
    void handleResponse_serviceThrowsException_doesNotPropagate() throws Exception {
        when(connectorRegistrationService.registerConnector(any()))
                .thenAnswer(invocation -> { throw new AlreadyExistException("Connector already exists"); });

        ConnectorRegistrationRequest regReq = ConnectorRegistrationRequest.builder()
                .name("duplicate-connector")
                .url("https://connector.example.com")
                .authType("none")
                .build();

        ProxyMessage message = ProxyMessage.builder()
                .proxyId("proxy-001")
                .messageType("connector.register")
                .timestamp(Instant.now())
                .connectorRegistrationRequest(regReq)
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();
    }
}
