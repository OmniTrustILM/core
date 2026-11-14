package com.otilm.core.security.ai;

import java.util.Objects;
import java.util.UUID;
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;

/** Installs native listeners after ordinary Core startup; failed listeners stay disabled. */
public final class RuntimeProxyTomcatBinding implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(RuntimeProxyTomcatBinding.class);
    private final RuntimeProxyTransport transport;
    private volatile State state = State.NEW;
    private Context context;
    private Connector ordinary;
    private TomcatWebServer owner;

    public RuntimeProxyTomcatBinding(RuntimeProxyTransport transport) {
        this.transport = Objects.requireNonNull(transport);
        for (Connector connector : transport.connectors().values()) {
            connector.addLifecycleListener(event -> {
                if (Lifecycle.BEFORE_STOP_EVENT.equals(event.getType())
                        || Lifecycle.BEFORE_DESTROY_EVENT.equals(event.getType())) {
                    transport.disable();
                }
            });
        }
    }

    public synchronized void configure(TomcatServletWebServerFactory factory) {
        if (state != State.NEW) {
            throw new IllegalStateException("Runtime binding already configured");
        }
        Objects.requireNonNull(factory);
        state = State.CONFIGURED;
        factory.addEngineValves(transport.boundary());
        factory.addContextCustomizers(this::installGuard);
        factory.addConnectorCustomizers(this::bindOrdinary);
    }

    private synchronized void bindOrdinary(Connector selected) {
        if (ordinary != null) {
            throw new IllegalStateException("Runtime binding ordinary connector unavailable");
        }
        ordinary = selected;
    }

    private synchronized void installGuard(Context selected) {
        if (context != null) {
            throw new IllegalStateException("Runtime binding context unavailable");
        }
        transport.installDispatchGuard(selected);
        context = selected;
    }

    public synchronized boolean start(TomcatWebServer server) {
        if (state == State.FAILED || state == State.CLOSED) {
            return false;
        }
        if (state == State.STARTED && owner == server) {
            return listenersStarted();
        }
        try {
            if (state != State.CONFIGURED || transport.disabled() || context == null
                    || !context.getState().isAvailable() || server == null || ordinary == null
                    || ordinary.getState() != LifecycleState.STARTED
                    || ordinary.getService() != server.getTomcat().getService() || ordinary.getLocalPort() <= 0
                    || !(context.getParent().getParent() instanceof Engine engine)
                    || engine.getService() != server.getTomcat().getService()) {
                return failedStart();
            }
            owner = server;
            for (Connector connector : transport.connectors().values()) {
                if (connector.getService() != null || connector.getState() != LifecycleState.NEW) {
                    return failedStart();
                }
            }
            for (Connector connector : transport.connectors().values()) {
                owner.getTomcat().getService().addConnector(connector);
                if (!connector.getState().isAvailable() || connector.getLocalPort() <= 0 || transport.disabled()) {
                    return failedStart();
                }
            }
            state = State.STARTED;
            log("attach", "AVAILABLE");
            return true;
        } catch (RuntimeException failure) {
            return failedStart();
        }
    }

    public boolean listenersStarted() {
        return state == State.STARTED && !transport.disabled()
                && transport.connectors().values().stream().allMatch(connector -> connector.getState().isAvailable());
    }

    private boolean failedStart() {
        transport.disable();
        boolean cleaned = detach();
        state = State.FAILED;
        log("attach", cleaned ? "UNAVAILABLE" : "CLEANUP_UNKNOWN");
        return false;
    }

    @Override
    public void close() {
        // Fence requests before waiting for an in-progress startup or cleanup owner.
        transport.disable();
        synchronized (this) {
            if (state == State.CLOSED) {
                return;
            }
            boolean cleaned = detach();
            state = cleaned ? State.CLOSED : State.FAILED;
            log("close", cleaned ? "CLOSED" : "CLEANUP_UNKNOWN");
        }
    }

    private boolean detach() {
        boolean complete = true;
        for (Connector connector : transport.connectors().values()) {
            if (!detach(connector)) {
                complete = false;
            }
        }
        return complete;
    }

    private static boolean detach(Connector connector) {
        var service = connector.getService();
        if (service == null && connector.getState() == LifecycleState.STOPPED) {
            // Boot may retain a detached connector for restart; only its owner can release that reference.
            return false;
        }
        boolean complete = true;
        try {
            if (connector.getState().isAvailable()) {
                connector.stop();
            }
        } catch (LifecycleException | RuntimeException failure) {
            complete = false;
        }
        try {
            if (connector.getState() != LifecycleState.DESTROYED) {
                connector.destroy();
            }
        } catch (LifecycleException | RuntimeException failure) {
            complete = false;
        }
        try {
            if (service != null) {
                service.removeConnector(connector);
            }
        } catch (RuntimeException failure) {
            complete = false;
        }
        boolean detached = connector.getState() == LifecycleState.DESTROYED && connector.getService() == null
                && connector.getLocalPort() < 0;
        return complete && detached;
    }

    private static void log(String operation, String code) {
        LOG.info("AI runtime listeners operation={} code={} correlation={}", operation, code, UUID.randomUUID());
    }

    private enum State {
        NEW,
        CONFIGURED,
        STARTED,
        FAILED,
        CLOSED
    }
}
