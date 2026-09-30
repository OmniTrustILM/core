package com.otilm.core.service.handler;

import com.otilm.core.config.KeyImportProperties;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

/**
 * Starts the key import reconciliation every {@code key-import.sweep-interval} while scheduled tasks are enabled. A
 * sweep calls connectors, so it runs on a thread of its own rather than on the scheduler's, which other tasks share; a
 * sweep still running when the next one is due is not started twice.
 */
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class KeyImportSweepScheduler implements SchedulingConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(KeyImportSweepScheduler.class);

    private final KeyImportSweeper sweeper;
    private final KeyImportProperties properties;
    private final AtomicBoolean sweeping = new AtomicBoolean();

    public KeyImportSweepScheduler(KeyImportSweeper sweeper, KeyImportProperties properties) {
        this.sweeper = sweeper;
        this.properties = properties;
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar registrar) {
        registrar.addFixedDelayTask(this::startSweep, properties.sweepInterval());
    }

    void startSweep() {
        if (sweeping.compareAndSet(false, true)) {
            Thread.ofVirtual().name("key-import-sweep").start(this::sweep);
        }
    }

    private void sweep() {
        try {
            sweeper.sweep();
        } catch (RuntimeException e) {
            logger
                    .warn("Key import reconciliation stopped ({}); it resumes at the next sweep",
                            e.getClass().getSimpleName());
        } finally {
            sweeping.set(false);
        }
    }
}
