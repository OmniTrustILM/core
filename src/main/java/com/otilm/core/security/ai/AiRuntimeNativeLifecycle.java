package com.otilm.core.security.ai;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.boot.web.server.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.event.ContextClosedEvent;

/** Adapts an optional trusted native binding to its owning servlet server's lifecycle. */
final class AiRuntimeNativeLifecycle
        implements
            WebServerFactoryCustomizer<TomcatServletWebServerFactory>,
            ApplicationListener<ApplicationEvent>,
            SmartLifecycle {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeNativeLifecycle.class);
    private final RuntimeProxyTomcatBinding binding;
    private final ApplicationContext owner;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean attached = new AtomicBoolean();
    private volatile boolean running;

    AiRuntimeNativeLifecycle(RuntimeProxyTomcatBinding binding, ApplicationContext owner) {
        this.binding = binding;
        this.owner = Objects.requireNonNull(owner);
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        if (binding != null && !closed.get()) {
            try {
                binding.configure(factory);
            } catch (RuntimeException failure) {
                unavailable("configure");
            }
        }
    }

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof ContextClosedEvent close && close.getApplicationContext() == owner) {
            stop();
        } else if (event instanceof ServletWebServerInitializedEvent initialized
                && initialized.getApplicationContext() == owner && binding != null && !closed.get()
                && initialized.getWebServer() instanceof TomcatWebServer server
                && attached.compareAndSet(false, true)) {
            try {
                if (!binding.start(server)) {
                    unavailable("attach");
                } else {
                    running = true;
                }
            } catch (RuntimeException failure) {
                unavailable("attach");
            }
        }
    }

    @Override
    public void start() {
        running = !closed.get();
    }

    @Override
    public void stop() {
        running = false;
        if (closed.compareAndSet(false, true) && binding != null) {
            try {
                binding.close();
            } catch (RuntimeException failure) {
                log("close", "CLEANUP_UNKNOWN");
            }
        }
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        } finally {
            callback.run();
        }
    }

    @Override
    public boolean isRunning() {
        return running && !closed.get();
    }

    @Override
    public int getPhase() {
        return WebServerApplicationContext.GRACEFUL_SHUTDOWN_PHASE + 1;
    }

    @Override
    public boolean isPauseable() {
        return false;
    }

    private void unavailable(String operation) {
        stop();
        log(operation, "UNAVAILABLE");
    }

    private static void log(String operation, String code) {
        LOG.warn("AI runtime lifecycle operation={} code={} correlation={}", operation, code, UUID.randomUUID());
    }
}
