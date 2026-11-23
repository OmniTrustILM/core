package com.otilm.ai.proxy;

import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(12)
class ProxyWireBudgetTest {
    @TempDir
    Path identity;

    @Test
    void aRunnerDrippingAValidFrameCannotKeepInputAliveOrStartAWorker() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-drip-");
        Path socket = directory.resolve("s");
        var starts = new AtomicInteger();
        var written = new AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(socket, fixture.configuration(), self(), () -> {
                    starts.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                })) {
            serve(server);
            try (var runner = SocketChannel.open(java.net.UnixDomainSocketAddress.of(socket))) {
                var bytes = new java.io.ByteArrayOutputStream();
                FrameCodec.writeRequest(bytes, ProxyWireFixtures.bootstrapRequest());
                Thread sender = Thread.ofPlatform().start(() -> {
                    try {
                        for (byte value : bytes.toByteArray()) {
                            Channels.newOutputStream(runner).write(value);
                            written.incrementAndGet();
                            Thread.sleep(150);
                        }
                    } catch (Exception expectedClosure) {
                    }
                });
                try {
                    long started = System.nanoTime();
                    assertEquals(-1, Channels.newInputStream(runner).read());
                    assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2));
                    assertTrue(written.get() >= 2);
                    assertEquals(0, starts.get());
                    assertEquals(0, fixture.requests.get());
                } finally {
                    runner.close();
                    sender.join(1000);
                    assertFalse(sender.isAlive());
                }
            }
        } finally {
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void unreadReplyDoesNotRetainTheChildOrPreventTheNextOwnedOperation() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-unread-");
        Path socket = directory.resolve("s");
        var firstHandler = new AtomicReference<Thread>();
        var firstChild = new AtomicReference<Process>();
        var starts = new AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(socket, fixture.configuration(), self(),
                        () -> new WorkerProcess(fixture.configuration(), (command, environment) -> {
                            var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
                            builder.environment().clear();
                            builder.environment().putAll(environment);
                            Process child = builder.start();
                            if (starts.incrementAndGet() == 1) {
                                firstChild.set(child);
                                firstHandler.set(Thread.currentThread());
                            }
                            return child;
                        }))) {
            serve(server);
            try (var unread = SocketChannel.open(java.net.UnixDomainSocketAddress.of(socket))) {
                FrameCodec.writeRequest(Channels.newOutputStream(unread), ProxyWireFixtures.bootstrapRequest());
                unread.shutdownOutput();
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while ((firstHandler.get() == null || firstHandler.get().isAlive()) && System.nanoTime() < until) {
                    java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
                }
                assertTrue(firstHandler.get() != null);
                assertFalse(firstHandler.get().isAlive());
                assertFalse(firstChild.get().isAlive());
                assertEquals(1, fixture.requests.get());
                try (var next = SocketChannel.open(java.net.UnixDomainSocketAddress.of(socket))) {
                    FrameCodec.writeRequest(Channels.newOutputStream(next), ProxyWireFixtures.bootstrapRequest());
                    next.shutdownOutput();
                    assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                            FrameCodec.readReply(Channels.newInputStream(next)).outcome());
                }
                assertEquals(2, fixture.requests.get());
                assertEquals(2, starts.get());
                assertTrue(server.healthy());
            } finally {
                Process child = firstChild.get();
                if (child != null && child.isAlive()) {
                    child.destroyForcibly();
                    assertTrue(child.waitFor(2, TimeUnit.SECONDS));
                }
            }
        } finally {
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }

    private static PeerPolicy self() throws Exception {
        var identity = new com.sun.security.auth.module.UnixSystem();
        var lookup = java.nio.file.FileSystems.getDefault().getUserPrincipalLookupService();
        return new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(identity.getUid())),
                lookup.lookupPrincipalByGroupName(Long.toString(identity.getGid())));
    }

    private static void serve(ProxyServer server) {
        Thread.ofPlatform().daemon().start(() -> {
            try {
                server.serve();
            } catch (java.io.IOException expectedClose) {
            }
        });
    }
}
