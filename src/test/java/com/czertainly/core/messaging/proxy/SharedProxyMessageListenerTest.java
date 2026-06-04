package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.core.messaging.proxy.handler.MessageTypeHandlerRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SharedProxyMessageListenerTest {

    @Mock
    private MessageTypeHandlerRegistry handlerRegistry;

    private SharedProxyMessageListener listener;

    @BeforeEach
    void setUp() {
        listener = new SharedProxyMessageListener(handlerRegistry);
    }

    @Test
    void processMessage_withRegisteredHandler_dispatches() throws Exception {
        ProxyMessage message = createMessage("health.check");
        when(handlerRegistry.dispatch(message)).thenReturn(true);

        listener.processMessage(message);

        verify(handlerRegistry).dispatch(message);
    }

    @Test
    void processMessage_noHandler_doesNotThrow() throws Exception {
        ProxyMessage message = createMessage("unknown.type");
        when(handlerRegistry.dispatch(message)).thenReturn(false);

        assertThatCode(() -> listener.processMessage(message)).doesNotThrowAnyException();
        verify(handlerRegistry).dispatch(message);
    }

    @Test
    void processMessage_withNullMessageType_doesNotDispatch() throws Exception {
        ProxyMessage message = createMessage(null);

        listener.processMessage(message);

        verify(handlerRegistry, never()).dispatch(any());
    }

    @Test
    void processMessage_withBlankMessageType_doesNotDispatch() throws Exception {
        ProxyMessage message = createMessage("  ");

        listener.processMessage(message);

        verify(handlerRegistry, never()).dispatch(any());
    }

    @Test
    void processMessage_withNullMessage_doesNotThrow() throws Exception {
        assertThatCode(() -> listener.processMessage(null)).doesNotThrowAnyException();
        verify(handlerRegistry, never()).dispatch(any());
    }

    private ProxyMessage createMessage(String messageType) {
        return ProxyMessage.builder()
                .proxyId("test-proxy")
                .messageType(messageType)
                .timestamp(Instant.now())
                .build();
    }
}
