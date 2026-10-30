package com.otilm.core.util;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import org.hibernate.resource.jdbc.spi.StatementInspector;

/**
 * Records the SQL Hibernate sends on the current thread while a test has recording switched on. Registered as the
 * session factory's statement inspector for the test profile; outside {@link #during} it passes every statement through
 * untouched.
 */
public class SqlCapture implements StatementInspector {

    private static final ThreadLocal<List<String>> RECORDING = new ThreadLocal<>();

    /** What an action returned, and the statements it sent in the order they were sent. */
    public record Captured<R>(R result, List<String> statements) {
    }

    @Override
    public String inspect(String sql) {
        List<String> recorded = RECORDING.get();
        if (recorded != null) {
            recorded.add(sql);
        }
        return sql;
    }

    /** Whether the current thread is recording, which it is only while {@link #during} runs its action. */
    public static boolean isRecording() {
        return RECORDING.get() != null;
    }

    public static <R> Captured<R> during(Callable<R> action) throws Exception {
        List<String> recorded = new ArrayList<>();
        RECORDING.set(recorded);
        try {
            R result = action.call();
            return new Captured<>(result, List.copyOf(recorded));
        } finally {
            RECORDING.remove();
        }
    }
}
