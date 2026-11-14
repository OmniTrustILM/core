package com.otilm.core.security.ai;

import org.junit.jupiter.api.Test;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServer;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.boot.web.server.servlet.context.ServletWebServerApplicationContext;
import org.springframework.boot.web.server.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.context.event.ContextClosedEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AiRuntimeNativeLifecycleTest {
    private final RuntimeProxyTomcatBinding binding = mock(RuntimeProxyTomcatBinding.class);
    private final ServletWebServerApplicationContext owner = mock(ServletWebServerApplicationContext.class);
    private final AiRuntimeNativeLifecycle lifecycle = new AiRuntimeNativeLifecycle(binding, owner);

    @Test
    void absentTransportLeavesOrdinaryFactoryAndLifecycleAlone() {
        var absent = new AiRuntimeNativeLifecycle(null, owner);
        var factory = new TomcatServletWebServerFactory();
        absent.customize(factory);
        absent.start();
        absent.onApplicationEvent(new ServletWebServerInitializedEvent(mock(TomcatWebServer.class), owner));
        absent.stop();
        assertThat(factory.getEngineValves()).isEmpty();
        assertThat(factory.getContextCustomizers()).isEmpty();
        assertThat(absent.isRunning()).isFalse();
    }

    @Test
    void configuresTheOwningFactoryBeforeStartingNativeConnectors() {
        var factory = new TomcatServletWebServerFactory();
        lifecycle.customize(factory);
        verify(binding).configure(factory);
        verify(binding, never()).start(org.mockito.ArgumentMatchers.any());
        var server = mock(TomcatWebServer.class);
        when(binding.start(server)).thenReturn(true);
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(server, owner));
        verify(binding).start(server);
        assertThat(lifecycle.isRunning()).isTrue();
    }

    @Test
    void foreignManagementContextAndOtherServerCannotAttach() {
        lifecycle
                .onApplicationEvent(new ServletWebServerInitializedEvent(mock(TomcatWebServer.class),
                        mock(ServletWebServerApplicationContext.class)));
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(mock(WebServer.class), owner));
        verifyNoInteractions(binding);
    }

    @Test
    void closesBeforeOrdinaryGracefulShutdownAndInvokesCompletionAfterTheFence() {
        assertThat(lifecycle.getPhase()).isGreaterThan(WebServerApplicationContext.GRACEFUL_SHUTDOWN_PHASE);
        assertThat(lifecycle.isPauseable()).isFalse();
        lifecycle.start();
        assertThat(lifecycle.isRunning()).isTrue();
        lifecycle.stop(() -> {
            verify(binding).close();
            assertThat(lifecycle.isRunning()).isFalse();
        });
    }

    @Test
    void terminalStopBlocksLateInitializationAndRestart() {
        lifecycle.start();
        lifecycle.stop();
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(mock(TomcatWebServer.class), owner));
        lifecycle.start();
        lifecycle.customize(new TomcatServletWebServerFactory());
        lifecycle.stop();
        verify(binding).close();
        verify(binding, never()).start(org.mockito.ArgumentMatchers.any());
        verify(binding, never()).configure(org.mockito.ArgumentMatchers.any());
        assertThat(lifecycle.isRunning()).isFalse();
    }

    @Test
    void ownerContextCloseFencesWhileForeignContextCloseHasNoEffect() {
        lifecycle.onApplicationEvent(new ContextClosedEvent(mock(ServletWebServerApplicationContext.class)));
        verifyNoInteractions(binding);
        lifecycle.onApplicationEvent(new ContextClosedEvent(owner));
        verify(binding).close();
    }

    @Test
    void failedAttachmentIsTerminalAndDoesNotRestartFromAnotherEvent() {
        var server = mock(TomcatWebServer.class);
        when(binding.start(server)).thenReturn(false);
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(server, owner));
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(server, owner));
        verify(binding).start(server);
        verify(binding).close();
        assertThat(lifecycle.isRunning()).isFalse();
    }

    @Test
    void unexpectedNativeStartFailureClosesWithoutSurfacingPrivateDetails() {
        var server = mock(TomcatWebServer.class);
        when(binding.start(server)).thenThrow(new IllegalStateException("synthetic-private-key-path"));
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(server, owner));
        verify(binding).close();
        assertThat(lifecycle.isRunning()).isFalse();
    }

    @Test
    void customizationFailureClosesAndFutureEventsCannotAttach() {
        var factory = new TomcatServletWebServerFactory();
        doThrow(new IllegalStateException("synthetic-native-configuration-path")).when(binding).configure(factory);
        lifecycle.customize(factory);
        lifecycle.onApplicationEvent(new ServletWebServerInitializedEvent(mock(TomcatWebServer.class), owner));
        verify(binding).close();
        verify(binding, never()).start(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void configurationWithAbsentOrAmbiguousTransportsDoesNotCustomizeOrdinaryFactory() {
        var beans = new org.springframework.beans.factory.support.StaticListableBeanFactory();
        var configuration = new AiRuntimeNativeConfiguration();
        var factory = new TomcatServletWebServerFactory();
        configuration
                .aiRuntimeNativeLifecycle(beans.getBeanProvider(RuntimeProxyTransport.class), owner)
                .customize(factory);
        beans.addBean("first", mock(RuntimeProxyTransport.class));
        beans.addBean("second", mock(RuntimeProxyTransport.class));
        configuration
                .aiRuntimeNativeLifecycle(beans.getBeanProvider(RuntimeProxyTransport.class), owner)
                .customize(factory);
        assertThat(factory.getEngineValves()).isEmpty();
        assertThat(factory.getContextCustomizers()).isEmpty();
    }

    @Test
    void configurationConnectsTheUniqueTrustedTransportToTheNativeBinding() {
        var beans = new org.springframework.beans.factory.support.StaticListableBeanFactory();
        var transport = mock(RuntimeProxyTransport.class);
        var valve = mock(org.apache.catalina.Valve.class);
        when(transport.connectors()).thenReturn(java.util.Map.of());
        when(transport.boundary()).thenReturn(valve);
        beans.addBean("transport", transport);
        var adapter = new AiRuntimeNativeConfiguration()
                .aiRuntimeNativeLifecycle(beans.getBeanProvider(RuntimeProxyTransport.class), owner);
        var factory = new TomcatServletWebServerFactory();
        adapter.customize(factory);
        assertThat(factory.getEngineValves()).containsExactly(valve);
        assertThat(factory.getContextCustomizers()).hasSize(1);
    }
}
