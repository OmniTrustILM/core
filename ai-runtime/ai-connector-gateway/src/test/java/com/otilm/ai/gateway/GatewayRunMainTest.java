package com.otilm.ai.gateway;

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

class GatewayRunMainTest {
    @TempDir
    Path directory;

    @Test
    void actualFiniteChildRecordsProtectedOutcomeAndPrintsOnlyMetadata() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            var child = child(GatewayRunMain.class.getName(), List.of(f.envelope.toString(), f.config.toString()));
            assertEquals(0, child.exit());
            assertTrue(child.output().matches("phase=gateway op=outcome code=RECORDED correlation=[0-9a-f-]{36}\\R"));
            assertEquals(1, f.consumes.get());
            assertEquals(1, f.sends.get());
            assertEquals(1, f.outcomes.get());
            assertFalse(child.output().contains("public reply"));
            assertFalse(child.output().contains(GatewayRunFixture.TOKEN));
            assertEquals("", child.error());
        }
    }

    @Test
    void actualInvalidChildHasNoRawPathOrExceptionOutput() throws Exception {
        var result = child(GatewayRunMain.class.getName(), List.of("/PRIVATE_PATH_CANARY"));
        assertEquals(1, result.exit());
        assertTrue(result.output().contains("code=UNKNOWN"));
        assertEquals("", result.error());
        assertFalse(result.output().contains("PRIVATE"));
    }

    @Test
    void returnedMainCannotLeaveAnUnexpectedNonDaemonThreadAlive() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            long start = System.nanoTime();
            var result = child(HangingOwner.class.getName(), List.of(f.envelope.toString(), f.config.toString()));
            long elapsed = System.nanoTime() - start;
            assertEquals(1, result.exit());
            assertTrue(elapsed >= TimeUnit.SECONDS.toNanos(5));
            assertTrue(elapsed < TimeUnit.SECONDS.toNanos(9));
            assertEquals(1, f.sends.get());
            assertEquals(1, result.output().lines().count());
            assertEquals("", result.error());
        }
    }

    public static final class HangingOwner {
        public static void main(String[] args) {
            Thread.ofPlatform().start(() -> {
                try {
                    Thread.sleep(30000);
                } catch (InterruptedException stopped) {
                    Thread.currentThread().interrupt();
                }
            });
            GatewayRunMain.main(args);
        }
    }

    record Child(int exit, String output, String error) {
    }

    static Child child(String main, List<String> args) throws Exception {
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
        java.lang.management.ManagementFactory
                .getRuntimeMXBean()
                .getInputArguments()
                .stream()
                .filter(a -> a.startsWith("-javaagent:") && a.contains("jacoco"))
                .forEach(command::add);
        command
                .addAll(List
                        .of("-XX:-PrintWarnings", "-XX:-UsePerfData", "-XX:+DisableAttachMechanism",
                                "-XX:-CreateCoredumpOnCrash", "-XX:-HeapDumpOnOutOfMemoryError",
                                "-XX:ErrorFile=/dev/null", "-XX:-FlightRecorder", "-cp",
                                System.getProperty("java.class.path"), main));
        command.addAll(args);
        var builder = new ProcessBuilder(command);
        builder.environment().clear();
        Process process = builder.start();
        try {
            assertTrue(process.waitFor(9, TimeUnit.SECONDS));
            byte[] output = process.getInputStream().readNBytes(4097),
                    error = process.getErrorStream().readNBytes(4097);
            assertTrue(output.length <= 4096);
            assertTrue(error.length <= 4096);
            return new Child(process.exitValue(), new String(output, StandardCharsets.UTF_8),
                    new String(error, StandardCharsets.UTF_8));
        } finally {
            process.destroyForcibly();
            assertTrue(process.waitFor(2, TimeUnit.SECONDS));
            process.getInputStream().close();
            process.getOutputStream().close();
            process.getErrorStream().close();
        }
    }
}
