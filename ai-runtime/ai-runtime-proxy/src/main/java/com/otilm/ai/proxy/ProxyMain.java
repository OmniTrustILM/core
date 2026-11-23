package com.otilm.ai.proxy;

import com.sun.management.HotSpotDiagnosticMXBean;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.Arrays;

/** Fixed pathname-UDS facade entry point. Its container must launch this JVM with a qualified clean profile. */
public final class ProxyMain {
    private ProxyMain() {
    }

    @FunctionalInterface
    interface Servers {
        ProxyServer create(Path socket, ProxyConfiguration configuration) throws java.io.IOException;
    }

    public static void main(String[] arguments) {
        try {
            if (run(arguments)) {
                return;
            }
        } catch (Throwable unavailable) {
        }
        failClosed();
    }

    static boolean run(String[] arguments) {
        return run(arguments, ProxyServer::new);
    }

    static boolean run(String[] arguments, Servers servers) {
        Thread.setDefaultUncaughtExceptionHandler((thread, unavailable) -> failClosed());
        if (arguments == null || arguments.length != 6 || !profileActive()) {
            System.err.println("phase=startup op=- code=DENIED correlation=-");
            return false;
        }
        try {
            ProxyConfiguration configuration = ProxyConfiguration.fromArguments(Arrays.copyOfRange(arguments, 1, 6));
            try (var server = servers.create(Path.of(arguments[0]), configuration)) {
                Thread shutdown = new Thread(server::close, "proxy-shutdown");
                Runtime.getRuntime().addShutdownHook(shutdown);
                try {
                    server.serve();
                } finally {
                    server.close();
                    try {
                        Runtime.getRuntime().removeShutdownHook(shutdown);
                    } catch (IllegalStateException shuttingDown) {
                    }
                }
                return server.healthy();
            }
        } catch (Exception unavailable) {
            return false;
        }
    }

    private static void failClosed() {
        try {
            System.err.println("phase=lifecycle op=- code=UNHEALTHY correlation=-");
        } finally {
            Runtime.getRuntime().halt(1);
        }
    }

    static boolean profileActive() {
        for (String variable : new String[]{"_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"}) {
            String value = System.getenv(variable);
            if (value != null && !value.isBlank()) {
                return false;
            }
        }
        // This check cannot undo pre-main injection; the immutable container launch must already be clean.
        try {
            HotSpotDiagnosticMXBean vm = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
            return option(vm, "UsePerfData", "false") && option(vm, "DisableAttachMechanism", "true")
                    && option(vm, "CreateCoredumpOnCrash", "false") && option(vm, "HeapDumpOnOutOfMemoryError", "false")
                    && option(vm, "FlightRecorder", "false") && option(vm, "ErrorFile", "/dev/null")
                    && option(vm, "DisplayVMOutputToStderr", "true");
        } catch (RuntimeException unsupportedProfile) {
            return false;
        }
    }

    private static boolean option(HotSpotDiagnosticMXBean vm, String name, String value) {
        return vm != null && value.equals(vm.getVMOption(name).getValue());
    }
}
