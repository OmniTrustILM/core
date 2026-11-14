package com.otilm.ai.runner;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(10)
class RunnerBootstrapMainTest {
    @Test
    void actualChildCompletesTwoFramesAndExitsWithMetadataOnly() throws Exception {
        try (var peer = new RunnerBootstrapTest.Peer("claimed")) {
            var result = child(arguments(peer.socket));
            assertEquals(0, result.exit());
            peer.awaitFrames(2);
            assertEquals(2, peer.frames.size());
            assertTrue(result.output().contains("op=bootstrap code=CLAIMED correlation="));
            assertTrue(result.output().contains("op=heartbeat code=ACK correlation="));
            assertFalse(result.output().contains(RunnerBootstrapTest.CLAIM.toString()));
            assertFalse(result.output().contains(peer.socket.toString()));
        }
    }

    @Test
    void anActualProtectedReplyFailureNeverLogsTheBodyOrResends() throws Exception {
        try (var peer = new RunnerBootstrapTest.Peer("bad-body")) {
            var result = child(arguments(peer.socket));
            assertEquals(1, result.exit());
            peer.awaitFrames(1);
            assertEquals(1, peer.frames.size());
            assertEquals("phase=runner op=- code=FAILED correlation=-", result.output().trim());
            assertFalse(result.output().contains("PRIVATE_BODY_CANARY"));
        }
    }

    @Test
    void wrongArgumentArityPathOrCanonicalUuidNeverOpensTheSocket() throws Exception {
        try (var peer = new RunnerBootstrapTest.Peer("claimed")) {
            assertFalse(RunnerBootstrapMain.run(null, System.nanoTime()));
            assertFalse(RunnerBootstrapMain.run(new String[0], System.nanoTime()));
            assertFalse(RunnerBootstrapMain.run(new String[]{"PRIVATE_PATH_CANARY"}, System.nanoTime()));
            String[] extra = java.util.Arrays.copyOf(arguments(peer.socket), 5);
            extra[4] = "PRIVATE_EXEC_CANARY";
            assertFalse(RunnerBootstrapMain.run(extra, System.nanoTime()));
            for (String value : List.of("not-uuid", "1-1-1-1-1")) {
                String[] invalid = arguments(peer.socket);
                invalid[1] = value;
                assertFalse(RunnerBootstrapMain.run(invalid, System.nanoTime()));
            }
            String[] relative = arguments(peer.socket);
            relative[0] = "relative.socket";
            assertFalse(RunnerBootstrapMain.run(relative, System.nanoTime()));
            assertEquals(0, peer.frames.size());
            var result = child(new String[]{"PRIVATE_PATH_CANARY"});
            assertEquals(1, result.exit());
            assertEquals("phase=runner op=- code=FAILED correlation=-", result.output().trim());
        }
    }

    private static String[] arguments(Path socket) {
        return new String[]{
                socket.toString(),
                RunnerBootstrapTest.RUN.toString(),
                RunnerBootstrapTest.ATTEMPT.toString(),
                RunnerBootstrapTest.POD.toString()};
    }

    private static ChildResult child(String[] arguments) throws Exception {
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
        java.lang.management.ManagementFactory
                .getRuntimeMXBean()
                .getInputArguments()
                .stream()
                .filter(argument -> argument.startsWith("-javaagent:") && argument.contains("jacoco"))
                .forEach(command::add);
        command.addAll(List.of("-cp", System.getProperty("java.class.path"), RunnerBootstrapMain.class.getName()));
        command.addAll(List.of(arguments));
        var builder = new ProcessBuilder(command).redirectErrorStream(true);
        builder.environment().clear();
        Process process = builder.start();
        try {
            assertTrue(process.waitFor(5, TimeUnit.SECONDS));
            byte[] output = process.getInputStream().readNBytes(4097);
            assertTrue(output.length <= 4096);
            return new ChildResult(process.exitValue(), new String(output, java.nio.charset.StandardCharsets.UTF_8));
        } finally {
            process.destroyForcibly();
            assertTrue(process.waitFor(2, TimeUnit.SECONDS));
        }
    }

    private record ChildResult(int exit, String output) {
    }
}
