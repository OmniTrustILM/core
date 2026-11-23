package com.otilm.ai.runner;

import java.nio.file.Path;
import java.util.UUID;

/** Fixed finite probe entry point. Arguments are copyable identifiers and grant no Core authority. */
public final class RunnerBootstrapMain {
    private RunnerBootstrapMain() {
    }

    public static void main(String[] arguments) {
        long started = System.nanoTime();
        try {
            if (run(arguments, started)) {
                return;
            }
        } catch (Throwable unavailable) {
        }
        System.out.println("phase=runner op=- code=FAILED correlation=-");
        System.exit(1);
    }

    static boolean run(String[] arguments, long started) {
        if (arguments == null || arguments.length != 4) {
            return false;
        }
        try {
            Path socket = Path.of(arguments[0]);
            UUID run = uuid(arguments[1]);
            UUID attempt = uuid(arguments[2]);
            UUID pod = uuid(arguments[3]);
            return new RunnerBootstrap(new LocalRpcClient(socket)).run(run, attempt, pod, started);
        } catch (Exception unavailable) {
            return false;
        }
    }

    private static UUID uuid(String text) {
        UUID value = UUID.fromString(text);
        if (!value.toString().equalsIgnoreCase(text)) {
            throw new IllegalArgumentException("RUNNER_CONFIG");
        }
        return value;
    }
}
