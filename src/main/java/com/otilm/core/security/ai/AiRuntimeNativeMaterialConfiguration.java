package com.otilm.core.security.ai;

import com.otilm.ai.proxy.IdentityFiles;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.service.ai.AiRuntimeControllerServiceImpl;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.core.env.Environment;

/** Optional infrastructure wiring; a configured file is never an execution-enable flag. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "otilm.ai.runtime.native-material-file")
@TraceMetadataOnly
public class AiRuntimeNativeMaterialConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeNativeMaterialConfiguration.class);

    @Bean(destroyMethod = "close")
    Materials aiRuntimeNativeMaterials(Environment environment, ObjectProvider<AiRuntimeNativeStartupWriter> writers) {
        AiRuntimeNativeMaterialPublisher publisher = null;
        boolean denialConfirmed = false;
        try {
            AiRuntimeNativeStartupWriter writer = writers.getIfUnique();
            if (writer == null) {
                throw new IllegalStateException("Native runtime confirmation unavailable");
            }
            disable(writer);
            denialConfirmed = true;
            String file = environment.getRequiredProperty("otilm.ai.runtime.native-material-file");
            String context = environment.getProperty("server.servlet.context-path", "/api");
            var material = AiRuntimeNativeMaterialFile.read(Path.of(file), context);
            var keys = IdentityFiles
                    .loadServerKeys(material.certificateFile(), material.privateKeyFile(), material.serverCaFile());
            Clock clock = Clock.systemUTC();
            publisher = new AiRuntimeNativeMaterialPublisher(material.policy(), clock);
            publisher.refresh(AiRuntimeOperationBudget.start());
            if (publisher.get() == null) {
                throw new IllegalStateException("Native runtime policy unavailable");
            }
            var listeners = new ArrayList<RuntimeProxyTransport.Listener>();
            for (var binding : material.listeners()) {
                listeners
                        .add(new RuntimeProxyTransport.Listener(binding.role(), binding.address(), binding.port(), keys,
                                new RuntimeProxyTrustManager(publisher, clock, binding.role())));
            }
            var transport = RuntimeProxyTransport.forListeners(material.contextPath(), listeners);
            var authority = new AiRuntimeControllerAuthority(material.controller());
            var workloadSource = new AiRuntimeControllerServiceImpl.Source(material.observation(),
                    material.workloadProfiles());
            return new Materials(transport, authority, workloadSource, publisher, writer);
        } catch (Exception unavailable) {
            if (publisher != null) {
                publisher.close();
            }
            LOG
                    .warn("AI runtime native material operation=startup status={}",
                            denialConfirmed ? "UNAVAILABLE" : "UNCONFIRMED");
            return new Materials(null, null, null, publisher, null);
        }
    }

    @Bean
    RuntimeProxyTransport aiRuntimeMaterialTransport(Materials material) {
        return material.transport;
    }

    @Bean
    AiRuntimeControllerAuthority aiRuntimeMaterialControllerAuthority(Materials material) {
        return material.authority;
    }

    @Bean(destroyMethod = "")
    AiRuntimeNativeMaterialPublisher aiRuntimeMaterialPolicyPublisher(Materials material) {
        return material.publisher;
    }

    @Bean
    AiRuntimeControllerServiceImpl.Source aiRuntimeMaterialWorkloadSource(Materials material) {
        return material.workloadSource;
    }

    @Bean
    ApplicationListener<ContextClosedEvent> aiRuntimeMaterialCloseListener(Materials material,
            ApplicationContext owner) {
        return event -> {
            if (event.getApplicationContext() == owner) {
                material.close();
            }
        };
    }

    private static void disable(AiRuntimeNativeStartupWriter writer) {
        writer.disableAndConfirm(AiRuntimeOperationBudget.start());
        LOG.debug("AI runtime native material operation=disable status=DISABLED");
    }

    static final class Materials implements SmartLifecycle, AutoCloseable {
        private final RuntimeProxyTransport transport;
        private final AiRuntimeControllerAuthority authority;
        private final AiRuntimeControllerServiceImpl.Source workloadSource;
        private final AiRuntimeNativeMaterialPublisher publisher;
        private final AiRuntimeNativeStartupWriter writer;
        private final ScheduledThreadPoolExecutor executor;
        private final AtomicBoolean started = new AtomicBoolean();
        private final AtomicBoolean poisoned = new AtomicBoolean();
        private final AtomicBoolean closed = new AtomicBoolean();

        Materials(RuntimeProxyTransport transport, AiRuntimeControllerAuthority authority,
                AiRuntimeControllerServiceImpl.Source workloadSource, AiRuntimeNativeMaterialPublisher publisher,
                AiRuntimeNativeStartupWriter writer) {
            this.transport = transport;
            this.authority = authority;
            this.workloadSource = workloadSource;
            this.publisher = publisher;
            this.writer = writer;
            if (transport == null) {
                executor = null;
            } else {
                executor = new ScheduledThreadPoolExecutor(1, action -> {
                    var thread = new Thread(action, "ilm-ai-native-material");
                    thread.setDaemon(true);
                    return thread;
                });
                executor.setRemoveOnCancelPolicy(true);
            }
        }

        @Override
        public void start() {
            if (executor != null && !closed.get() && started.compareAndSet(false, true)) {
                try {
                    refresh();
                    if (!closed.get() && !poisoned.get()) {
                        executor.scheduleWithFixedDelay(this::refresh, 5, 5, TimeUnit.SECONDS);
                    }
                } catch (RuntimeException unavailable) {
                    poison();
                }
            }
        }

        void refresh() {
            if (transport == null || closed.get() || poisoned.get()) {
                return;
            }
            try {
                if (transport.disabled()) {
                    poison();
                    return;
                }
                publisher.refresh(AiRuntimeOperationBudget.start());
                if (publisher.get() == null) {
                    poison();
                }
            } catch (RuntimeException unavailable) {
                poison();
            }
        }

        private void poison() {
            if (transport != null && poisoned.compareAndSet(false, true)) {
                transport.disable();
                publisher.close();
                executor.shutdown();
                try {
                    disable(writer);
                } catch (RuntimeException unavailable) {
                    LOG.warn("AI runtime native material operation=disable status=UNCONFIRMED");
                }
                LOG.warn("AI runtime native material operation=refresh status=UNAVAILABLE");
            }
        }

        @Override
        public void stop() {
            close();
        }

        @Override
        public boolean isRunning() {
            return started.get() && !poisoned.get() && !closed.get();
        }

        @Override
        public int getPhase() {
            return WebServerApplicationContext.START_STOP_LIFECYCLE_PHASE - 1;
        }

        @Override
        public boolean isPauseable() {
            return false;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                if (transport != null) {
                    transport.disable();
                }
                if (publisher != null) {
                    publisher.close();
                }
                if (executor == null) {
                    return;
                }
                executor.shutdownNow();
                try {
                    if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                        LOG.warn("AI runtime native material operation=close status=CLEANUP_UNKNOWN");
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    LOG.warn("AI runtime native material operation=close status=CLEANUP_UNKNOWN");
                }
            }
        }
    }
}
