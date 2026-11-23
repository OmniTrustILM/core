package com.otilm.ai.gateway;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Fixed finite run process; no ingress daemon, provider selector or model-use grant. */
public final class GatewayRunMain {
    private GatewayRunMain() {
    }

    public static void main(String[] arguments) {
        run(arguments, System.nanoTime(), GatewayRun.Audience.RUN);
    }

    static void run(String[] arguments, long started, GatewayRun.Audience audience) {
        var terminal = new AtomicBoolean();
        var correlation = new AtomicReference<>("-");
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        Thread.setDefaultUncaughtExceptionHandler((thread, unavailable) -> {
            metadata(terminal, correlation.get(), "UNKNOWN", audience);
            Runtime.getRuntime().halt(1);
        });
        var cutoff = Executors
                .newSingleThreadScheduledExecutor(
                        Thread.ofPlatform().daemon().name("gateway-process-cutoff").factory());
        cutoff.schedule(() -> {
            metadata(terminal, correlation.get(), "UNKNOWN", audience);
            Runtime.getRuntime().halt(1);
        }, Math.max(0, TimeUnit.SECONDS.toNanos(6) - (System.nanoTime() - started)), TimeUnit.NANOSECONDS);
        try {
            var transport = new ChatCompletionsTransport();
            var deadline = transport.accepted(started);
            UUID call = UUID.randomUUID();
            correlation.set(call.toString());
            if (arguments == null || arguments.length != 2) {
                throw GatewayRunWire.invalid();
            }
            for (String name : new String[]{"_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"}) {
                String value = System.getenv(name);
                if (value != null && !value.isBlank()) {
                    throw GatewayRunWire.invalid();
                }
            }
            GatewayRun.execute(Path.of(arguments[0]), Path.of(arguments[1]), transport, deadline, call, audience);
            metadata(terminal, call.toString(), "RECORDED", audience);
        } catch (Throwable unavailable) {
            metadata(terminal, correlation.get(), "UNKNOWN", audience);
            System.exit(1);
        } finally {
            // Keep the delayed daemon cutoff queued if an unexpected non-daemon thread outlives Main.
            cutoff.shutdown();
        }
    }

    private static void metadata(AtomicBoolean terminal, String correlation, String code,
            GatewayRun.Audience audience) {
        if (terminal.compareAndSet(false, true)) {
            System.out
                    .println("phase=gateway op=" + (code.equals("RECORDED") ? audience.operation() : "-") + " code="
                            + code + " correlation=" + correlation);
        }
    }
}
