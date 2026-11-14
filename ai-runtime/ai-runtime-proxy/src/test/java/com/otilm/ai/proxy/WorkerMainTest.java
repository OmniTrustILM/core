package com.otilm.ai.proxy;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WorkerMainTest {
    @TempDir
    Path directory;

    @Test
    void consumesExactlyOneRequestAndWritesExactlyOneBoundedReply() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            Process process = worker(fixture.configuration());
            try {
                FrameCodec.writeRequest(process.getOutputStream(), WireBodies.bootstrap());
                process.getOutputStream().close();
                byte[] output = process.getInputStream().readNBytes(4125);
                assertTrue(process.waitFor(7, TimeUnit.SECONDS));
                assertEquals(0, process.exitValue());
                ProxyReply reply = FrameCodec.readReply(new ByteArrayInputStream(output));
                assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, reply.outcome());
                assertArrayEquals(WireBodies.PENDING, reply.payload());
                assertEquals(1, fixture.requests.get());
            } finally {
                process.destroyForcibly();
                assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void rejectsExtraFrameBytesWithoutOpeningAnUpstreamConnection() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            Process process = worker(fixture.configuration());
            try {
                FrameCodec.writeRequest(process.getOutputStream(), WireBodies.bootstrap());
                process.getOutputStream().write(0);
                process.getOutputStream().close();
                assertEquals(0, process.getInputStream().readNBytes(4125).length);
                assertTrue(process.waitFor(7, TimeUnit.SECONDS));
                assertEquals(0, fixture.connections.get());
            } finally {
                process.destroyForcibly();
                assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void workerOwnBudgetStopsAnInputWithoutEof() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            Process process = worker(fixture.configuration());
            try {
                FrameCodec.writeRequest(process.getOutputStream(), WireBodies.bootstrap());
                process.getOutputStream().flush();
                assertTrue(process.waitFor(7, TimeUnit.SECONDS));
                assertEquals(0, process.getInputStream().readNBytes(4125).length);
                assertEquals(0, fixture.connections.get());
            } finally {
                process.destroyForcibly();
                assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void aLingeringNonDaemonDependencyCannotOutliveTheWorkerCutoff() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            Process process = worker(fixture.configuration(), LingeringDependencyWorker.class.getName());
            try {
                FrameCodec.writeRequest(process.getOutputStream(), WireBodies.bootstrap());
                process.getOutputStream().close();
                byte[] frame = process.getInputStream().readNBytes(28 + WireBodies.PENDING.length);
                assertEquals(28 + WireBodies.PENDING.length, frame.length);
                assertTrue(process.waitFor(7, TimeUnit.SECONDS));
                assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                        FrameCodec.readReply(new ByteArrayInputStream(frame)).outcome());
                assertEquals(1, fixture.requests.get());
            } finally {
                process.destroyForcibly();
                assertTrue(process.waitFor(3, TimeUnit.SECONDS));
            }
        }
    }

    public static final class LingeringDependencyWorker {
        public static void main(String[] arguments) {
            Thread.ofPlatform().daemon(false).start(() -> {
                try {
                    new java.util.concurrent.CountDownLatch(1).await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            });
            WorkerMain.main(arguments);
        }
    }

    private static Process worker(ProxyConfiguration configuration) throws Exception {
        return worker(configuration, WorkerMain.class.getName());
    }

    private static Process worker(ProxyConfiguration configuration, String mainClass) throws Exception {
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
                        .of("-cp", System.getProperty("java.class.path"), mainClass,
                                configuration.coreOrigin().toString(), configuration.coreAddress().getHostAddress(),
                                configuration.certificateFile().toString(), configuration.privateKeyFile().toString(),
                                configuration.serverCaFile().toString()));
        return new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    }
}
