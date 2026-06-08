package com.czertainly.core.signing.record;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

/**
 * The {@code signing_record.*} meter catalog. Modelled as a funnel; see {@code docs/signing-record-metrics.md}
 * for the full design (stages, invariants, and the queries each meter answers).
 *
 * <p>Counter names are written in Micrometer (dotted) form; the Prometheus registry auto-appends {@code _total}
 * and converts dots to underscores, so {@code signing_record.intake} exports as {@code signing_record_intake_total}.
 */
@Component
public class SigningRecordMetrics {

    // intake.failed reasons — the synchronous handoff refusal per mode
    public static final String REASON_PERSIST_ERROR = "persist_error";   // IMMEDIATE synchronous persist threw
    public static final String REASON_SAVE_ERROR = "save_error";         // DEFERRED_DURABLE outbox save threw
    public static final String REASON_INTERRUPTED = "interrupted";       // BEST_EFFORT BLOCK admission interrupted

    // deletion types
    public static final String DELETE_TYPE_AFTER_RETRIEVAL = "after_retrieval";                   // read-path, per record
    public static final String DELETE_TYPE_AFTER_RETRIEVAL_FALLBACK = "after_retrieval_fallback"; // fallback sweep
    public static final String DELETE_TYPE_EXPIRED = "expired";                                   // retention sweep

    private final MeterRegistry registry;

    public SigningRecordMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    // --- Stage 1: intake funnel — one tick per record() call ------------------------------------------

    /**
     * All intake attempts (every {@code record()} call), the funnel denominator.
     */
    public Counter intake(String mode) {
        return Counter.builder("signing_record.intake").tag("mode", mode).register(registry);
    }

    /**
     * Intake calls dropped because the record policy has no recordable content.
     */
    public Counter intakeSkipped(String mode) {
        return Counter.builder("signing_record.intake.skipped").tag("mode", mode).register(registry);
    }

    /**
     * Intake calls whose synchronous handoff was refused; {@code reason} is one of the {@code REASON_*} constants.
     */
    public Counter intakeFailed(String mode, String reason) {
        return Counter.builder("signing_record.intake.failed").tag("mode", mode).tag("reason", reason).register(registry);
    }

    // --- Stage 2: persist — records reaching signing_record (all modes) -------------------------------

    /**
     * Persist attempts: IMMEDIATE synchronous persist, BEST_EFFORT flush batch, DEFERRED_DURABLE drain rows.
     */
    public Counter persist(String mode) {
        return Counter.builder("signing_record.persist").tag("mode", mode).register(registry);
    }

    /** Persist attempts that failed. */
    public Counter persistFailed(String mode) {
        return Counter.builder("signing_record.persist.failed").tag("mode", mode).register(registry);
    }

    // --- Best-effort backpressure loss (post-acceptance) ---------------------------------------------

    /**
     * Older queued records dropped by the DROP_OLDEST backpressure policy. Standalone saturation signal.
     */
    public Counter bestEffortEvicted() {
        return registry.counter("signing_record.best_effort.evicted");
    }

    // --- Deletion ------------------------------------------------------------------------------------

    /**
     * Records removed, across all three deletion {@code type}s — the unified records-deleted series.
     */
    public Counter deleted(String type) {
        return Counter.builder("signing_record.deleted").tag("type", type).register(registry);
    }

    /**
     * Read-path per-record delete failures ({@code type=after_retrieval}).
     */
    public Counter deleteFailed(String type) {
        return Counter.builder("signing_record.delete.failed").tag("type", type).register(registry);
    }

    /**
     * Background sweep firings that ran (post-lock) — the run-level denominator for the batch jobs.
     */
    public Counter sweep(String type) {
        return Counter.builder("signing_record.sweep").tag("type", type).register(registry);
    }

    /**
     * Background sweep firings that aborted.
     */
    public Counter sweepFailed(String type) {
        return Counter.builder("signing_record.sweep.failed").tag("type", type).register(registry);
    }

    // --- Timing --------------------------------------------------------------------------------------

    public Timer writeDuration(String mode) {
        return Timer.builder("signing_record.write.duration").tag("mode", mode).register(registry);
    }

    /**
     * Runs {@code action}, recording its duration under {@link #writeDuration(String)} for {@code mode}.
     */
    public void timed(String mode, Runnable action) {
        Timer.Sample sample = Timer.start(registry);
        try {
            action.run();
        } finally {
            sample.stop(writeDuration(mode));
        }
    }
}
