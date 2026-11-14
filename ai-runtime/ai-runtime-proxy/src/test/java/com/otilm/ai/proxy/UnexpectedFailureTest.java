package com.otilm.ai.proxy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(9)
class UnexpectedFailureTest {
    @org.junit.jupiter.api.io.TempDir
    Path outputDirectory;

    @Test
    void aSignalRunsTheRegisteredHookAndAcknowledgesSocketCleanup() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-signal-");
        Path socket = directory.resolve("s");
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
        java.lang.management.ManagementFactory
                .getRuntimeMXBean()
                .getInputArguments()
                .stream()
                .filter(argument -> argument.startsWith("-javaagent:") && argument.contains("jacoco"))
                .forEach(command::add);
        command
                .addAll(List
                        .of("-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash",
                                "-XX:-HeapDumpOnOutOfMemoryError", "-XX:ErrorFile=/dev/null", "-XX:-FlightRecorder",
                                "-XX:+DisplayVMOutputToStderr", "-cp", System.getProperty("java.class.path"),
                                SignalProbe.class.getName(), socket.toString(), "https://core.test", "127.0.0.1",
                                "/identity/tls.crt", "/identity/tls.key", "/trust/ca.pem"));
        Path output = outputDirectory.resolve("signal-out");
        Path error = outputDirectory.resolve("signal-err");
        var builder = new ProcessBuilder(command).redirectOutput(output.toFile()).redirectError(error.toFile());
        builder.environment().clear();
        Process process = builder.start();
        try {
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (!Files.exists(socket) && process.isAlive() && System.nanoTime() < until) {
                java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
            }
            assertTrue(Files.exists(socket));
            java.nio.channels.SocketChannel connected = null;
            while (connected == null && process.isAlive() && System.nanoTime() < until) {
                try {
                    connected = java.nio.channels.SocketChannel.open(java.net.UnixDomainSocketAddress.of(socket));
                } catch (java.net.ConnectException notListeningYet) {
                    java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
                }
            }
            assertTrue(connected != null);
            try (var peer = connected) {
                peer.shutdownOutput();
                assertEquals(-1, java.nio.channels.Channels.newInputStream(peer).read());
            }
            // An admitted-and-closed socket proves serve() was entered after the hook was registered.
            process.destroy();
            assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            assertFalse(Files.exists(socket));
            assertEquals(0, Files.size(output));
            String metadata = Files.readString(error);
            assertFalse(metadata.contains("Exception"));
            assertFalse(metadata.contains(directory.toString()));
        } finally {
            process.destroyForcibly();
            assertTrue(process.waitFor(2, TimeUnit.SECONDS));
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void unexpectedParentThreadFailureHaltsWithOnlyControlledMetadata() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-failure-");
        Path socket = directory.resolve("s");
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
        java.lang.management.ManagementFactory
                .getRuntimeMXBean()
                .getInputArguments()
                .stream()
                .filter(argument -> argument.startsWith("-javaagent:") && argument.contains("jacoco"))
                .forEach(command::add);
        command
                .addAll(List
                        .of("-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash",
                                "-XX:-HeapDumpOnOutOfMemoryError", "-XX:ErrorFile=/dev/null", "-XX:-FlightRecorder",
                                "-XX:+DisplayVMOutputToStderr", "-cp", System.getProperty("java.class.path"),
                                FailureProbe.class.getName(), socket.toString(), "https://core.test", "127.0.0.1",
                                "/identity/tls.crt", "/identity/tls.key", "/trust/ca.pem"));
        var builder = new ProcessBuilder(command);
        builder.environment().clear();
        Process process = builder.start();
        try {
            assertTrue(process.waitFor(3, TimeUnit.SECONDS), "uncaught failure must terminate the owner");
            assertEquals(1, process.exitValue());
            assertEquals(0, process.getInputStream().readNBytes(512).length);
            String metadata = new String(process.getErrorStream().readNBytes(4096),
                    java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(metadata.contains("phase=lifecycle op=- code=UNHEALTHY correlation=-"));
            assertFalse(metadata.contains("PRIVATE_PATH_CANARY"));
            assertFalse(metadata.contains("IllegalStateException"));
        } finally {
            process.destroyForcibly();
            assertTrue(process.waitFor(2, TimeUnit.SECONDS));
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }

    public static final class FailureProbe {
        public static void main(String[] arguments) {
            ProxyMain.run(arguments, (path, configuration) -> {
                var self = new com.sun.security.auth.module.UnixSystem();
                var lookup = java.nio.file.FileSystems.getDefault().getUserPrincipalLookupService();
                var policy = new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(self.getUid())),
                        lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
                var server = new ProxyServer(path, configuration, policy, () -> new WorkerProcess(configuration));
                Thread.ofPlatform().name("synthetic-failure").start(() -> {
                    throw new IllegalStateException("PRIVATE_PATH_CANARY");
                });
                return server;
            });
        }
    }

    public static final class SignalProbe {
        public static void main(String[] arguments) {
            ProxyMain.run(arguments, (path, configuration) -> {
                var self = new com.sun.security.auth.module.UnixSystem();
                var lookup = java.nio.file.FileSystems.getDefault().getUserPrincipalLookupService();
                var policy = new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(self.getUid())),
                        lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
                return new ProxyServer(path, configuration, policy, () -> new WorkerProcess(configuration));
            });
        }
    }
}
