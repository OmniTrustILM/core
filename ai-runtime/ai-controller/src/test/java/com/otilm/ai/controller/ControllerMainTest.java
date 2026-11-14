package com.otilm.ai.controller;

import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Actual child JVM privacy/finite controls do not prove Kubernetes, current CSI or Core authority. */
class ControllerMainTest {
    @TempDir
    Path directory;

    @Test
    void malformedArgumentsAndPrivateConfigurationPathsProduceOnlyFixedTerminalMetadata() throws Exception {
        for (List<String> arguments : List
                .of(List.<String>of(), List.of("synthetic-private-cli-canary"),
                        List
                                .of(directory.resolve("private-missing-config-canary").toString(),
                                        "e7a0989e-4cd6-42d7-baf6-344caf843551", "d00f5707-e1ad-41e0-9f21-b66c74358c99"),
                        List.of("/synthetic-private-path-canary", "not-an-id-private-canary", "also-private-canary"),
                        List
                                .of("/synthetic-private-path-canary", "e7a0989e-4cd6-42d7-baf6-344caf843551",
                                        "d00f5707-e1ad-41e0-9f21-b66c74358c99", "unknown-mode-canary"))) {
            var result = child(arguments, false);
            assertEquals(1, result.exit());
            assertTrue(result.output().matches("phase=controller op=- code=UNKNOWN correlation=[0-9a-f-]{36}\\R"),
                    "stdout must contain one bounded fixed metadata event");
            assertFalse(result.output().contains("canary"));
            assertFalse(result.output().contains(directory.toString()));
            assertTrue(result.output().getBytes(StandardCharsets.UTF_8).length < 256);
        }
    }

    @Test
    void detectedAmbientJavaOptionsDenyBeforeConfigurationOrNetworkWithoutEchoingTheirValues() throws Exception {
        var result = child(List
                .of(directory.resolve("private-config-canary").toString(), "e7a0989e-4cd6-42d7-baf6-344caf843551",
                        "d00f5707-e1ad-41e0-9f21-b66c74358c99"),
                true);
        assertEquals(1, result.exit());
        assertTrue(result.output().matches("phase=controller op=- code=UNKNOWN correlation=[0-9a-f-]{36}\\R"));
        assertFalse(result.output().contains("private"));
    }

    Result child(List<String> arguments, boolean options) throws Exception {
        var command = new ArrayList<>(List
                .of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-XX:+DisableAttachMechanism",
                        "-XX:-UsePerfData", "-XX:-HeapDumpOnOutOfMemoryError", "-XX:-CreateCoredumpOnCrash",
                        "-XX:ErrorFile=/dev/null", "-Xlog:all=off", "-cp", System.getProperty("java.class.path"),
                        "com.otilm.ai.controller.ControllerMain"));
        command.addAll(arguments);
        ManagementFactory
                .getRuntimeMXBean()
                .getInputArguments()
                .stream()
                .filter(value -> value.startsWith("-javaagent:") && value.contains("org.jacoco.agent"))
                .forEach(value -> command.add(1, value));
        var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().clear();
        if (options) {
            // This harmless option is already interpreted by the JVM before Main; native env admission is separate.
            builder.environment().put("JAVA_TOOL_OPTIONS", "-Dsynthetic.controller=private-options-canary");
        }
        var process = builder.start();
        try {
            assertTrue(process.waitFor(8, TimeUnit.SECONDS), "finite controller child did not terminate");
            byte[] output = process.getInputStream().readNBytes(4097);
            assertTrue(output.length <= 4096);
            assertFalse(process.isAlive());
            return new Result(process.exitValue(), new String(output, StandardCharsets.UTF_8));
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(1, TimeUnit.SECONDS), "owned child was not reaped");
            }
            process.getInputStream().close();
            process.getOutputStream().close();
            process.getErrorStream().close();
        }
    }

    record Result(int exit, String output) {
    }
}
