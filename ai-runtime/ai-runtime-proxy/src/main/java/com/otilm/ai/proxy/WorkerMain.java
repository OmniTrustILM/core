package com.otilm.ai.proxy;

import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Fixed worker entry point. Its parent owns process termination, descriptor closure and reaping. */
public final class WorkerMain {
    private WorkerMain() {
    }

    public static void main(String[] arguments) {
        long started = System.nanoTime();
        var watchdog = Executors
                .newSingleThreadScheduledExecutor(Thread.ofPlatform().daemon().name("worker-cutoff").factory());
        // Closing stdin is not a reliable way to interrupt a blocked pipe read.
        watchdog
                .schedule(() -> Runtime.getRuntime().halt(0),
                        Math.max(1, CoreRpcClient.BUDGET_NANOS - (System.nanoTime() - started)), TimeUnit.NANOSECONDS);
        try {
            ProxyConfiguration configuration = ProxyConfiguration.fromArguments(arguments);
            ProxyRequest request = FrameCodec.readRequest(System.in);
            ProxyReply reply = new CoreRpcClient(configuration).execute(request, started);
            FrameCodec.writeReply(System.out, reply);
            System.out.flush();
        } catch (Exception unavailable) {
            // The parent treats a missing complete reply as UNKNOWN. No raw failure reaches either pipe.
        } finally {
            // A lingering non-daemon dependency must not cancel the process-local cutoff.
            watchdog.shutdown();
        }
    }
}
