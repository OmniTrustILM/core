package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.entity.Proxy;
import com.czertainly.core.dao.repository.ProxyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link HealthCheckHandler}.
 * Tests health check message handling and proxy status updates.
 */
@ExtendWith(MockitoExtension.class)
class HealthCheckHandlerTest {

    @Mock
    private ProxyRepository proxyRepository;

    private HealthCheckHandler handler;

    @BeforeEach
    void setUp() {
        handler = new HealthCheckHandler(proxyRepository);
    }

    @Test
    void handleResponse_withValidMessage_updatesProxyStatus() {
        Proxy proxy = new Proxy();
        proxy.setCode("proxy-001");
        proxy.setStatus(ProxyStatus.DISCONNECTED);

        when(proxyRepository.findByCode("proxy-001")).thenReturn(Optional.of(proxy));

        ProxyMessage message = ProxyMessage.builder()
                .proxyId("proxy-001")
                .messageType("health.check")
                .timestamp(Instant.now())
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();

        verify(proxyRepository).findByCode("proxy-001");
        verify(proxyRepository).save(proxy);
        assertThat(proxy.getStatus()).isEqualTo(ProxyStatus.CONNECTED);
        assertThat(proxy.getLastActivity()).isNotNull();
    }

    @Test
    void handleResponse_withUnknownProxy_logsWarningWithoutError() {
        when(proxyRepository.findByCode("unknown-proxy")).thenReturn(Optional.empty());

        ProxyMessage message = ProxyMessage.builder()
                .proxyId("unknown-proxy")
                .messageType("health.check")
                .timestamp(Instant.now())
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();

        verify(proxyRepository).findByCode("unknown-proxy");
        verify(proxyRepository, never()).save(any());
    }

    @Test
    void handleResponse_withNullProxyId_skipsRepositoryLookup() {
        ProxyMessage message = ProxyMessage.builder()
                .proxyId(null)
                .messageType("health.check")
                .timestamp(Instant.now())
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();

        verify(proxyRepository, never()).findByCode(any());
        verify(proxyRepository, never()).save(any());
    }

    @Test
    void handleResponse_withBlankProxyId_skipsRepositoryLookup() {
        ProxyMessage message = ProxyMessage.builder()
                .proxyId("   ")
                .messageType("health.check")
                .timestamp(Instant.now())
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();

        verify(proxyRepository, never()).findByCode(any());
        verify(proxyRepository, never()).save(any());
    }

    @Test
    void handleResponse_withNullTimestamp_handlesGracefully() {
        Proxy proxy = new Proxy();
        proxy.setCode("proxy-001");

        when(proxyRepository.findByCode("proxy-001")).thenReturn(Optional.of(proxy));

        ProxyMessage message = ProxyMessage.builder()
                .proxyId("proxy-001")
                .messageType("health.check")
                .timestamp(null)
                .build();

        assertThatCode(() -> handler.handleResponse(message)).doesNotThrowAnyException();
    }
}
