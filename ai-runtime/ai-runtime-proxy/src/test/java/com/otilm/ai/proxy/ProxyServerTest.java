package com.otilm.ai.proxy;

import com.sun.security.auth.module.UnixSystem;
import java.io.ByteArrayOutputStream;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(12)
class ProxyServerTest {
    @Test
    void aDirectoryOwnedByADifferentPrincipalIsRejectedBeforeMutation() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-owner-");
        String previous = System.getProperty("user.name");
        var permissions = Files.getPosixFilePermissions(directory);
        var root = directory.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName("0");
        try (var fixture = new LocalTlsFixture(identity)) {
            System.setProperty("user.name", Files.getOwner(directory).equals(root) ? "65532" : "0");
            var failure = assertThrows(java.io.IOException.class, () -> new ProxyServer(directory.resolve("s"),
                    fixture.configuration(), selfPolicy(), () -> new WorkerProcess(fixture.configuration())));
            assertEquals("SOCKET_PROFILE", failure.getMessage());
            assertEquals(permissions, Files.getPosixFilePermissions(directory));
            assertFalse(Files.exists(directory.resolve("s")));
        } finally {
            System.setProperty("user.name", previous);
            Files.deleteIfExists(directory.resolve("s"));
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void aNondedicatedDirectoryIsRefusedBeforeItsPermissionsOrContentsAreChanged() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-shared-dir-");
        Path canary = Files.writeString(directory.resolve("canary"), "PRIVATE_CANARY");
        var permissions = Files.getPosixFilePermissions(directory);
        try (var fixture = new LocalTlsFixture(identity)) {
            assertThrows(java.io.IOException.class, () -> new ProxyServer(directory.resolve("s"),
                    fixture.configuration(), selfPolicy(), () -> new WorkerProcess(fixture.configuration())));
            assertEquals(permissions, Files.getPosixFilePermissions(directory));
            assertEquals("PRIVATE_CANARY", Files.readString(canary));
        } finally {
            Files.deleteIfExists(directory.resolve("s"));
            Files.deleteIfExists(canary);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void admissionThreadStartErrorClosesTheAcceptedSocketAndPoisonsTheFacade() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-start-error-");
        Path path = directory.resolve("s");
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(),
                        () -> new WorkerProcess(fixture.configuration()),
                        () -> java.util.concurrent.Executors.newScheduledThreadPool(2), thread -> {
                            throw new OutOfMemoryError("PRIVATE_START_CANARY");
                        })) {
            var ended = new java.util.concurrent.CountDownLatch(1);
            Thread serving = Thread.ofPlatform().start(() -> {
                try {
                    server.serve();
                } catch (Throwable ignored) {
                } finally {
                    ended.countDown();
                }
            });
            try (var client = SocketChannel.open(UnixDomainSocketAddress.of(path))) {
                assertTrue(ended.await(1, TimeUnit.SECONDS));
                assertFalse(server.healthy());
                assertEquals(-1, client.read(java.nio.ByteBuffer.allocate(1)));
            } finally {
                server.close();
                serving.join(1000);
            }
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void closeAcknowledgmentCannotPassAnAcceptedOperationStillBeingStarted() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-start-close-");
        Path path = directory.resolve("s");
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var closed = new java.util.concurrent.CountDownLatch(1);
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(),
                        () -> new WorkerProcess(fixture.configuration()),
                        () -> java.util.concurrent.Executors.newScheduledThreadPool(2), thread -> {
                            entered.countDown();
                            try {
                                release.await();
                            } catch (InterruptedException interrupted) {
                                throw new IllegalStateException(interrupted);
                            }
                            thread.start();
                        })) {
            Thread serving = serve(server);
            try (var client = SocketChannel.open(UnixDomainSocketAddress.of(path))) {
                assertTrue(entered.await(1, TimeUnit.SECONDS));
                Thread closer = Thread.ofPlatform().start(() -> {
                    server.close();
                    closed.countDown();
                });
                try {
                    assertFalse(closed.await(100, TimeUnit.MILLISECONDS));
                } finally {
                    release.countDown();
                }
                assertTrue(closed.await(2, TimeUnit.SECONDS));
                assertEquals(-1, client.read(java.nio.ByteBuffer.allocate(1)));
                closer.join(1000);
            } finally {
                release.countDown();
                server.close();
                serving.join(1000);
            }
        } finally {
            release.countDown();
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @TempDir
    Path identity;

    @Test
    void servesOneActualWorkerReplyOverAPermissionRestrictedPathnameSocket() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-facade-");
        Path path = directory.resolve("s");
        try (var fixture = new LocalTlsFixture(identity)) {
            try (var server = new ProxyServer(path, fixture.configuration(), selfPolicy(),
                    () -> new WorkerProcess(fixture.configuration()))) {
                Thread loop = serve(server);
                assertTrue(Files.exists(path));
                assertEquals("rw-rw----", PosixFilePermissions.toString(Files.getPosixFilePermissions(path)));
                try (var client = connect(path)) {
                    FrameCodec.writeRequest(Channels.newOutputStream(client), ProxyWireFixtures.bootstrapRequest());
                    client.shutdownOutput();
                    assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                            FrameCodec.readReply(Channels.newInputStream(client)).outcome());
                }
                assertEquals(1, fixture.requests.get());
                server.close();
                loop.join(2000);
                assertTrue(!loop.isAlive());
            }
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"json", "extra"})
    void extraBytesAndMalformedJsonNeverCreateAWorker(String mode) throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-facade-");
        Path path = directory.resolve("s");
        AtomicInteger creates = new AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(), () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                })) {
            serve(server);
            assertTrue(Files.exists(path));
            var frame = new ByteArrayOutputStream();
            FrameCodec.writeRequest(frame, ProxyWireFixtures.bootstrapRequest());
            byte[] invalid = mode.equals("json")
                    ? frame.toByteArray()
                    : java.util.Arrays.copyOf(frame.toByteArray(), frame.size() + 1);
            if (mode.equals("json")) {
                invalid[26] = '!';
            }
            try (var client = connect(path)) {
                Channels.newOutputStream(client).write(invalid);
                if (mode.equals("json")) {
                    client.shutdownOutput();
                }
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertEquals(0, creates.get());
            assertEquals(0, fixture.requests.get());
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void missingEofIsCutOffBeforeAnyWorkerStarts() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-facade-");
        Path path = directory.resolve("s");
        AtomicInteger creates = new AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(), () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                })) {
            serve(server);
            assertTrue(Files.exists(path));
            try (var client = connect(path)) {
                FrameCodec.writeRequest(Channels.newOutputStream(client), ProxyWireFixtures.bootstrapRequest());
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertEquals(0, creates.get());
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void rejectsAtCapacityWithoutQueueingAnotherWorker() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-capacity-");
        Path path = directory.resolve("s");
        AtomicInteger creates = new AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(), () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                })) {
            fixture.stall = true;
            serve(server);
            try (var first = connect(path)) {
                FrameCodec.writeRequest(Channels.newOutputStream(first), ProxyWireFixtures.bootstrapRequest());
                first.shutdownOutput();
                fixture.requestArrived.get(4, TimeUnit.SECONDS);
                try (var second = connect(path)) {
                    assertEquals(-1, Channels.newInputStream(second).read());
                }
                assertEquals(1, creates.get());
                assertEquals(-1, Channels.newInputStream(first).read());
                assertEquals(1, fixture.requests.get());
            }
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void aWrongKernelUserIsDeniedBeforeAnyWorkerOrFrame() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-peer-deny-");
        Path path = directory.resolve("s");
        AtomicInteger creates = new AtomicInteger();
        var self = new UnixSystem();
        var lookup = FileSystems.getDefault().getUserPrincipalLookupService();
        var wrong = new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(self.getUid() == 0 ? 65532 : 0)),
                lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), wrong, () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                })) {
            serve(server);
            try (var client = connect(path)) {
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertEquals(0, creates.get());
            assertTrue(server.healthy());
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void failedReapLatchesUnhealthyAndDeniesEveryLaterConnection() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-unhealthy-");
        Path path = directory.resolve("s");
        AtomicInteger creates = new AtomicInteger();
        var frame = new ByteArrayOutputStream();
        FrameCodec
                .writeReply(frame, new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, ProxyWireFixtures.CALL, 200,
                        ProxyWireFixtures.PENDING));
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(), () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration(),
                            (command, environment) -> new WorkerProcessTest.Unreapable(frame.toByteArray()));
                })) {
            serve(server);
            try (var client = connect(path)) {
                FrameCodec.writeRequest(Channels.newOutputStream(client), ProxyWireFixtures.bootstrapRequest());
                client.shutdownOutput();
                assertEquals(ProxyReply.Outcome.UNKNOWN,
                        FrameCodec.readReply(Channels.newInputStream(client)).outcome());
            }
            assertFalse(server.healthy());
            try (var client = connect(path)) {
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertEquals(1, creates.get());
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void refusingAnExistingPathPreservesItsOriginalBytes() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-existing-");
        Path path = directory.resolve("s");
        Files.writeString(path, "PRIVATE_FILE_CANARY");
        try (var fixture = new LocalTlsFixture(identity)) {
            assertThrows(java.io.IOException.class, () -> new ProxyServer(path, fixture.configuration(), selfPolicy(),
                    () -> new WorkerProcess(fixture.configuration())));
            assertEquals("PRIVATE_FILE_CANARY", Files.readString(path));
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void concurrentCloseWaitsForTheSameActualCleanupAcknowledgment() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-close-");
        Path path = directory.resolve("s");
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var firstDone = new java.util.concurrent.CountDownLatch(1);
        var secondDone = new java.util.concurrent.CountDownLatch(1);
        var owned = new java.util.concurrent.atomic.AtomicReference<Process>();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(),
                        () -> new WorkerProcess(fixture.configuration(), (command, environment) -> {
                            entered.countDown();
                            try {
                                release.await(3, TimeUnit.SECONDS);
                            } catch (InterruptedException interrupted) {
                                Thread.currentThread().interrupt();
                            }
                            Process child = new ProcessBuilder(
                                    Path.of(System.getProperty("java.home"), "bin/java").toString(), "-cp",
                                    System.getProperty("java.class.path"), WorkerProcessTest.Hang.class.getName())
                                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                                    .start();
                            owned.set(child);
                            return child;
                        }))) {
            serve(server);
            try (var client = connect(path)) {
                FrameCodec.writeRequest(Channels.newOutputStream(client), ProxyWireFixtures.bootstrapRequest());
                client.shutdownOutput();
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                Thread first = Thread.ofPlatform().daemon().start(() -> {
                    server.close();
                    firstDone.countDown();
                });
                assertEquals(-1, Channels.newInputStream(client).read());
                Thread second = Thread.ofPlatform().daemon().start(() -> {
                    server.close();
                    secondDone.countDown();
                });
                try {
                    assertFalse(secondDone.await(100, TimeUnit.MILLISECONDS));
                    assertFalse(server.healthy(), "cleanup has not acknowledged a healthy closed state");
                } finally {
                    release.countDown();
                }
                assertTrue(firstDone.await(3, TimeUnit.SECONDS));
                assertTrue(secondDone.await(3, TimeUnit.SECONDS));
                first.join(1000);
                second.join(1000);
                assertFalse(owned.get().isAlive());
                assertTrue(owned.get().waitFor(1, TimeUnit.SECONDS));
            }
        } finally {
            release.countDown();
            if (owned.get() != null) {
                owned.get().destroyForcibly();
                owned.get().waitFor();
            }
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void anAcceptedPeerLookupIsOwnedEvenBeforeIdentityResolutionFinishes() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-peer-close-");
        Path path = directory.resolve("s");
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var peerClosed = new java.util.concurrent.CountDownLatch(1);
        var closeDone = new java.util.concurrent.CountDownLatch(1);
        var self = new UnixSystem();
        var lookup = FileSystems.getDefault().getUserPrincipalLookupService();
        var actual = lookup.lookupPrincipalByName(Long.toString(self.getUid()));
        var stalled = new java.nio.file.attribute.UserPrincipal() {
            @Override
            public String getName() {
                return actual.getName();
            }

            @Override
            public int hashCode() {
                return actual.hashCode();
            }

            @Override
            public boolean equals(Object other) {
                entered.countDown();
                try {
                    release.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                return actual.equals(other);
            }
        };
        var policy = new PeerPolicy(stalled, lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
        AtomicInteger creates = new AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), policy, () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                })) {
            Thread loop = serve(server);
            try (var client = connect(path)) {
                FrameCodec.writeRequest(Channels.newOutputStream(client), ProxyWireFixtures.bootstrapRequest());
                client.shutdownOutput();
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                Thread reader = Thread.ofPlatform().daemon().start(() -> {
                    try {
                        Channels.newInputStream(client).read();
                    } catch (java.io.IOException closed) {
                    } finally {
                        peerClosed.countDown();
                    }
                });
                Thread closer = Thread.ofPlatform().daemon().start(() -> {
                    server.close();
                    closeDone.countDown();
                });
                try {
                    assertTrue(peerClosed.await(500, TimeUnit.MILLISECONDS));
                } finally {
                    release.countDown();
                }
                assertTrue(closeDone.await(3, TimeUnit.SECONDS));
                loop.join(1000);
                reader.join(1000);
                closer.join(1000);
                assertEquals(0, creates.get());
            }
        } finally {
            release.countDown();
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void aReplacementSocketPathIsNeverDeletedAsIfItWereOwned() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-replaced-");
        Path path = directory.resolve("s");
        Path moved = directory.resolve("old");
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(),
                        () -> new WorkerProcess(fixture.configuration()))) {
            Files.move(path, moved);
            Files.writeString(path, "REPLACEMENT_CANARY");
            server.close();
            assertFalse(server.healthy());
            assertEquals("REPLACEMENT_CANARY", Files.readString(path));
            server.close();
        } finally {
            Files.deleteIfExists(path);
            Files.deleteIfExists(moved);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void aSymlinkedDirectoryAndRelativePathCannotBecomeTheListener() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-dir-");
        Path link = Path.of(directory + "-link");
        try (var fixture = new LocalTlsFixture(identity)) {
            Files.createSymbolicLink(link, directory);
            assertThrows(java.io.IOException.class, () -> new ProxyServer(link.resolve("s"), fixture.configuration(),
                    selfPolicy(), () -> new WorkerProcess(fixture.configuration())));
            assertThrows(java.io.IOException.class, () -> new ProxyServer(Path.of("relative.sock"),
                    fixture.configuration(), selfPolicy(), () -> new WorkerProcess(fixture.configuration())));
            assertThrows(java.io.IOException.class, () -> new ProxyServer(Path.of("/"), fixture.configuration(),
                    selfPolicy(), () -> new WorkerProcess(fixture.configuration())));
        } finally {
            Files.deleteIfExists(link);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void failedFacadeWatchdogSetupClosesThePeerAndPermanentlyDeniesWork() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-timer-");
        Path path = directory.resolve("s");
        AtomicInteger creates = new AtomicInteger();
        var scheduler = java.util.concurrent.Executors.newScheduledThreadPool(2);
        scheduler.shutdown();
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(), () -> {
                    creates.incrementAndGet();
                    return new WorkerProcess(fixture.configuration());
                }, () -> scheduler)) {
            serve(server);
            try (var client = connect(path)) {
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertFalse(server.healthy());
            try (var client = connect(path)) {
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertEquals(0, creates.get());
        } finally {
            scheduler.shutdownNow();
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void aFatalTrustedWorkerFailurePoisonsAdmissionWithoutAnUncaughtRawCause() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-fatal-");
        Path path = directory.resolve("s");
        var raw = new java.util.concurrent.atomic.AtomicReference<Throwable>();
        var previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, failure) -> raw.set(failure));
        try (var fixture = new LocalTlsFixture(identity);
                var server = new ProxyServer(path, fixture.configuration(), selfPolicy(), () -> {
                    throw new AssertionError("PRIVATE_FATAL_CANARY");
                })) {
            serve(server);
            try (var client = connect(path)) {
                FrameCodec.writeRequest(Channels.newOutputStream(client), ProxyWireFixtures.bootstrapRequest());
                client.shutdownOutput();
                assertEquals(-1, Channels.newInputStream(client).read());
            }
            assertFalse(server.healthy());
            assertEquals(null, raw.get());
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous);
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    private static Thread serve(ProxyServer server) {
        return Thread.ofPlatform().daemon().start(() -> {
            try {
                server.serve();
            } catch (java.io.IOException expectedClose) {
            }
        });
    }

    private static SocketChannel connect(Path path) throws Exception {
        return SocketChannel.open(UnixDomainSocketAddress.of(path));
    }

    private static PeerPolicy selfPolicy() throws Exception {
        var identity = new UnixSystem();
        var lookup = FileSystems.getDefault().getUserPrincipalLookupService();
        return new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(identity.getUid())),
                lookup.lookupPrincipalByGroupName(Long.toString(identity.getGid())));
    }
}
