package com.otilm.ai.proxy;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(12)
class ProxyMainTest {
    @Test
    void aMissingFixedProfileOrArgumentsFailsStartupWithoutOpeningASocket() throws Exception {
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-cp",
                System.getProperty("java.class.path"), ProxyMain.class.getName(), "PRIVATE_PATH_CANARY")
                .redirectErrorStream(false)
                .start();
        try {
            assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            assertEquals(1, process.exitValue());
            assertEquals(0, process.getInputStream().readNBytes(512).length);
            String metadata = new String(process.getErrorStream().readNBytes(512),
                    java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(metadata.contains("phase=startup"));
            assertTrue(metadata.contains("code=DENIED"));
            assertFalse(metadata.contains("PRIVATE_PATH_CANARY"));
        } finally {
            process.destroyForcibly();
            assertTrue(process.waitFor(2, TimeUnit.SECONDS));
        }
    }

    @Test
    void invalidAdministratorArityNeverReachesTheListenerFactory() {
        var previous = Thread.getDefaultUncaughtExceptionHandler();
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        ProxyMain.Servers factory = (socket, configuration) -> {
            calls.incrementAndGet();
            throw new java.io.IOException("UNEXPECTED_FACTORY");
        };
        try {
            assertFalse(ProxyMain.run(null, factory));
            assertFalse(ProxyMain.run(new String[0], factory));
            assertFalse(ProxyMain.run(new String[]{"a", "b", "c", "d", "e"}, factory));
            assertEquals(0, calls.get());
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "qualified",
            "perf",
            "attach",
            "core",
            "heap",
            "jfr",
            "error-file",
            "stdout",
            "environment-jdk",
            "environment-tool",
            "environment-legacy"})
    void checksTheActualJdkProfileBeforeAdmission(String mode) throws Exception {
        var flags = new java.util.ArrayList<String>(java.util.List
                .of("-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash",
                        "-XX:-HeapDumpOnOutOfMemoryError", "-XX:ErrorFile=/dev/null", "-XX:-FlightRecorder",
                        "-XX:+DisplayVMOutputToStderr"));
        switch (mode) {
            case "perf" -> flags.set(0, "-XX:+UsePerfData");
            case "attach" -> flags.set(1, "-XX:-DisableAttachMechanism");
            case "core" -> flags.set(2, "-XX:+CreateCoredumpOnCrash");
            case "heap" -> flags.set(3, "-XX:+HeapDumpOnOutOfMemoryError");
            case "jfr" -> flags.set(5, "-XX:+FlightRecorder");
            case "error-file" -> flags.set(4, "-XX:ErrorFile=/private/tmp/synthetic-error-pattern");
            case "stdout" -> flags.set(6, "-XX:-DisplayVMOutputToStderr");
            default -> {
            }
        }
        var command = new java.util.ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
        java.lang.management.ManagementFactory
                .getRuntimeMXBean()
                .getInputArguments()
                .stream()
                .filter(argument -> argument.startsWith("-javaagent:") && argument.contains("jacoco"))
                .forEach(command::add);
        command.addAll(flags);
        command.addAll(java.util.List.of("-cp", System.getProperty("java.class.path"), ProfileProbe.class.getName()));
        var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().clear();
        if (mode.startsWith("environment-")) {
            String name = switch (mode) {
                case "environment-tool" -> "JAVA_TOOL_OPTIONS";
                case "environment-legacy" -> "_JAVA_OPTIONS";
                default -> "JDK_JAVA_OPTIONS";
            };
            builder.environment().put(name, "-Dilm.synthetic.option=1");
        }
        Process process = builder.start();
        try {
            assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            assertEquals(0, process.exitValue());
            assertEquals(mode.equals("qualified") ? "true" : "false",
                    new String(process.getInputStream().readNBytes(32), java.nio.charset.StandardCharsets.UTF_8)
                            .trim());
        } finally {
            process.destroyForcibly();
            assertTrue(process.waitFor(2, TimeUnit.SECONDS));
        }
    }

    public static final class ProfileProbe {
        public static void main(String[] arguments) {
            System.out.println(ProxyMain.profileActive());
        }
    }

    @Test
    void runsTheQualifiedLifecycleWithAnActualLocalPeerAndOwnedWorker() throws Exception {
        Path socketDirectory = java.nio.file.Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-main-");
        Path socket = socketDirectory.resolve("s");
        Path identity = java.nio.file.Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-main-id-");
        try (var fixture = new LocalTlsFixture(identity)) {
            var configuration = fixture.configuration();
            var command = new java.util.ArrayList<String>();
            command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
            java.lang.management.ManagementFactory
                    .getRuntimeMXBean()
                    .getInputArguments()
                    .stream()
                    .filter(argument -> argument.startsWith("-javaagent:") && argument.contains("jacoco"))
                    .forEach(command::add);
            command
                    .addAll(java.util.List
                            .of("-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash",
                                    "-XX:-HeapDumpOnOutOfMemoryError", "-XX:ErrorFile=/dev/null", "-XX:-FlightRecorder",
                                    "-XX:+DisplayVMOutputToStderr", "-cp", System.getProperty("java.class.path"),
                                    LifecycleProbe.class.getName(), socket.toString(),
                                    configuration.coreOrigin().toString(), configuration.coreAddress().getHostAddress(),
                                    configuration.certificateFile().toString(),
                                    configuration.privateKeyFile().toString(),
                                    configuration.serverCaFile().toString()));
            var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().clear();
            Process process = builder.start();
            try {
                assertTrue(process.waitFor(7, TimeUnit.SECONDS));
                assertEquals(0, process.exitValue());
                assertEquals("true:UPSTREAM_REPLY",
                        new String(process.getInputStream().readNBytes(128), java.nio.charset.StandardCharsets.UTF_8)
                                .trim());
                assertEquals(1, fixture.requests.get());
                assertFalse(java.nio.file.Files.exists(socket));
            } finally {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                assertTrue(process.waitFor(2, TimeUnit.SECONDS));
            }
        } finally {
            java.nio.file.Files.deleteIfExists(socket);
            java.nio.file.Files.deleteIfExists(socketDirectory);
            try (var files = java.nio.file.Files.list(identity)) {
                for (Path file : files.toList()) {
                    java.nio.file.Files.deleteIfExists(file);
                }
            }
            java.nio.file.Files.deleteIfExists(identity);
        }
    }

    public static final class LifecycleProbe {
        public static void main(String[] arguments) throws Exception {
            var outcome = new java.util.concurrent.atomic.AtomicReference<>(ProxyReply.Outcome.UNKNOWN);
            boolean healthy = ProxyMain.run(arguments, (path, configuration) -> {
                var self = new com.sun.security.auth.module.UnixSystem();
                var lookup = java.nio.file.FileSystems.getDefault().getUserPrincipalLookupService();
                var policy = new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(self.getUid())),
                        lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
                var server = new ProxyServer(path, configuration, policy, () -> new WorkerProcess(configuration));
                Thread.ofPlatform().daemon().start(() -> {
                    try (var client = java.nio.channels.SocketChannel.open(java.net.UnixDomainSocketAddress.of(path))) {
                        FrameCodec
                                .writeRequest(java.nio.channels.Channels.newOutputStream(client),
                                        WireBodies.bootstrap());
                        client.shutdownOutput();
                        outcome.set(FrameCodec.readReply(java.nio.channels.Channels.newInputStream(client)).outcome());
                    } catch (Exception unavailable) {
                    } finally {
                        server.close();
                    }
                });
                return server;
            });
            System.out.println(healthy + ":" + outcome.get().name());
        }
    }

}
