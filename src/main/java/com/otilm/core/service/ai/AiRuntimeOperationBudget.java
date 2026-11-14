package com.otilm.core.service.ai;

import com.otilm.api.exception.PlatformException;
import java.time.Duration;
import java.time.Instant;
import java.util.function.LongSupplier;

/** Trusted Core-local elapsed budget, never a wire timestamp, identity proof or grant. */
public final class AiRuntimeOperationBudget {
    private static final Duration MAXIMUM = Duration.ofSeconds(5);
    private final long durationNanos;
    private final long started;
    private final LongSupplier nanos;

    private AiRuntimeOperationBudget(Duration timeout, LongSupplier nanos) {
        if (timeout == null || nanos == null || timeout.isZero() || timeout.isNegative()
                || timeout.compareTo(MAXIMUM) > 0) {
            throw new IllegalArgumentException("Runtime operation budget must be positive and at most five seconds");
        }
        this.durationNanos = timeout.toNanos();
        this.nanos = nanos;
        this.started = nanos.getAsLong();
    }

    public static AiRuntimeOperationBudget start() {
        return start(MAXIMUM);
    }

    static AiRuntimeOperationBudget start(LongSupplier nanos) {
        return start(MAXIMUM, nanos);
    }

    public static AiRuntimeOperationBudget start(Duration timeout) {
        return start(timeout, System::nanoTime);
    }

    static AiRuntimeOperationBudget start(Duration timeout, LongSupplier nanos) {
        return new AiRuntimeOperationBudget(timeout, nanos);
    }

    public Duration remaining() {
        boolean interrupted = Thread.currentThread().isInterrupted();
        long remaining = durationNanos - (nanos.getAsLong() - started);
        if (interrupted || remaining <= 0) {
            throw new Unavailable(interrupted);
        }
        return Duration.ofNanos(Math.min(remaining, durationNanos));
    }

    /** Call only after the real database time read returns; floor PostgreSQL microseconds. */
    public Instant databaseCutoff(Instant returnedDatabaseTime) {
        long micros = remaining().toNanos() / 1000;
        if (micros == 0) {
            throw new Unavailable(false);
        }
        return returnedDatabaseTime.plusNanos(micros * 1000);
    }

    public static final class Unavailable extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;
        private final boolean interrupted;

        public Unavailable(boolean interrupted) {
            super("Runtime operation unavailable", null, false, false);
            this.interrupted = interrupted;
        }

        public boolean interrupted() {
            return interrupted;
        }
    }
}
