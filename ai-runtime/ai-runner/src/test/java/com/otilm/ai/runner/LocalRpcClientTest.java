package com.otilm.ai.runner;

import com.otilm.ai.proxy.FrameCodec;
import com.otilm.ai.proxy.LocalOperation;
import com.otilm.ai.proxy.ProxyReply;
import com.otilm.ai.proxy.ProxyRequest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(12)
class LocalRpcClientTest {
    private static final UUID CALL = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final byte[] BODY = "{\"protocolVersion\":1,\"runId\":\"00000000-0000-4000-8000-000000000002\",\"attemptId\":\"00000000-0000-4000-8000-000000000003\",\"podUid\":\"00000000-0000-4000-8000-000000000004\"}"
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final ProxyRequest REQUEST = new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, BODY);

    @Test
    void sendsExactlyOneFrameAndHalfCloseBeforeReceivingAnOpaqueMaximumReply() throws Exception {
        byte[] payload = new byte[4096];
        Arrays.fill(payload, (byte) 7);
        try (var peer = new Peer("normal", reply(1, CALL, 200, payload))) {
            ProxyReply result = new LocalRpcClient(peer.socket).exchange(REQUEST, TimeUnit.SECONDS.toNanos(3));
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, result.outcome());
            assertEquals(200, result.httpStatus());
            assertArrayEquals(payload, result.payload());
            assertEquals(REQUEST, peer.received.get(1, TimeUnit.SECONDS));
            assertEquals(1, peer.frames.get());
            assertEquals(1, peer.totalConnections());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3})
    void returnsTypedNonSuccessWithoutRetrying(int outcome) throws Exception {
        try (var peer = new Peer("normal", reply(outcome, CALL, 0, new byte[0]))) {
            ProxyReply result = new LocalRpcClient(peer.socket).exchange(REQUEST, TimeUnit.SECONDS.toNanos(3));
            assertEquals(outcome == 2 ? ProxyReply.Outcome.NOT_SENT : ProxyReply.Outcome.UNKNOWN, result.outcome());
            assertEquals(1, peer.frames.get());
            assertEquals(1, peer.totalConnections());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"extra", "truncated", "wrong-id", "bad-magic"})
    void rejectsMalformedExtraOrUncorrelatedFramesWithoutAnotherConnection(String mode) throws Exception {
        UUID otherCall = UUID.fromString("00000000-0000-4000-8000-000000000099");
        byte[] bytes = reply(1, mode.equals("wrong-id") ? otherCall : CALL, 200, new byte[]{7});
        if (mode.equals("extra")) {
            bytes = Arrays.copyOf(bytes, bytes.length + 1);
        } else if (mode.equals("truncated")) {
            bytes = Arrays.copyOf(bytes, bytes.length - 1);
        } else if (mode.equals("bad-magic")) {
            bytes[0] = 0;
        }
        try (var peer = new Peer("normal", bytes)) {
            IOException denied = assertThrows(IOException.class,
                    () -> new LocalRpcClient(peer.socket).exchange(REQUEST, TimeUnit.SECONDS.toNanos(3)));
            assertEquals("LOCAL_RPC_FAILED", denied.getMessage());
            assertNull(denied.getCause());
            assertEquals(1, peer.frames.get());
            assertEquals(1, peer.totalConnections());
        }
    }

    @Test
    void aValidMaximumReplyPlusOneByteIsRejectedBeforeThePeerCloses() throws Exception {
        byte[] bytes = reply(1, CALL, 200, new byte[4096]);
        bytes = Arrays.copyOf(bytes, bytes.length + 1);
        try (var peer = new Peer("no-eof", bytes)) {
            long started = System.nanoTime();
            IOException denied = assertThrows(IOException.class,
                    () -> new LocalRpcClient(peer.socket).exchange(REQUEST, TimeUnit.SECONDS.toNanos(3)));
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1));
            assertEquals("LOCAL_RPC_FAILED", denied.getMessage());
            assertNull(denied.getCause());
            assertTrue(peer.responseWritten.await(1, TimeUnit.SECONDS));
            assertEquals(1, peer.frames.get());
            assertEquals(1, peer.totalConnections());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"stall", "no-read", "drip", "no-eof"})
    void callerBudgetIncludesWritesReadsAndTheRequiredReplyEof(String mode) throws Exception {
        try (var peer = new Peer(mode, reply(1, CALL, 200, new byte[]{7}))) {
            long started = System.nanoTime();
            assertThrows(IOException.class,
                    () -> new LocalRpcClient(peer.socket).exchange(REQUEST, TimeUnit.SECONDS.toNanos(1)));
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3));
            assertEquals(1, peer.totalConnections());
            if (!mode.equals("no-read")) {
                assertEquals(1, peer.frames.get());
            }
        }
    }

    @Test
    void anUnboundedCallerAllowanceStillEndsAtTheEightSecondExchangeCap() throws Exception {
        try (var peer = new Peer("stall", reply(1, CALL, 200, new byte[]{7}))) {
            long started = System.nanoTime();
            assertThrows(IOException.class, () -> new LocalRpcClient(peer.socket).exchange(REQUEST, Long.MAX_VALUE));
            long elapsed = System.nanoTime() - started;
            assertTrue(elapsed >= TimeUnit.SECONDS.toNanos(7));
            assertTrue(elapsed < TimeUnit.SECONDS.toNanos(10));
            assertEquals(1, peer.frames.get());
        }
    }

    @Test
    void anExpiredCallerBudgetNeverConnects() throws Exception {
        try (var peer = new Peer("normal", reply(1, CALL, 200, new byte[]{7}))) {
            var client = new LocalRpcClient(peer.socket);
            assertThrows(IOException.class, () -> client.exchange(REQUEST, 0));
            assertThrows(IOException.class, () -> client.exchange(REQUEST, -1));
            assertThrows(IOException.class, () -> client.exchange(REQUEST, Long.MIN_VALUE));
            assertEquals(0, peer.totalConnections());
        }
    }

    @Test
    void anInterruptedOwnerDoesNotConnectAndKeepsItsInterruptSignal() throws Exception {
        try (var peer = new Peer("normal", reply(1, CALL, 200, new byte[]{7}))) {
            Thread.currentThread().interrupt();
            try {
                assertThrows(IOException.class,
                        () -> new LocalRpcClient(peer.socket).exchange(REQUEST, TimeUnit.SECONDS.toNanos(1)));
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            assertEquals(0, peer.totalConnections());
        }
    }

    @Test
    void onlyAnAbsoluteNormalizedPathnameIsAccepted() {
        for (Path invalid : new Path[]{null, Path.of("relative.sock"), Path.of("/tmp/../tmp/socket"), Path.of("/")}) {
            var denied = assertThrows(IllegalArgumentException.class, () -> new LocalRpcClient(invalid));
            assertEquals("LOCAL_RPC_FAILED", denied.getMessage());
        }
    }

    @Test
    void anUnavailablePathFailsWithoutExposingItsName() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-absent-");
        try {
            IOException denied = assertThrows(IOException.class,
                    () -> new LocalRpcClient(directory.resolve("PRIVATE_PATH_CANARY"))
                            .exchange(REQUEST, TimeUnit.SECONDS.toNanos(1)));
            assertEquals("LOCAL_RPC_FAILED", denied.getMessage());
            assertNull(denied.getCause());
        } finally {
            Files.delete(directory);
        }
    }

    private static byte[] reply(int outcome, UUID call, int status, byte[] payload) {
        return ByteBuffer
                .allocate(28 + payload.length)
                .putInt(0x494c4d52)
                .put((byte) 1)
                .put((byte) outcome)
                .putLong(call.getMostSignificantBits())
                .putLong(call.getLeastSignificantBits())
                .putShort((short) status)
                .putInt(payload.length)
                .put(payload)
                .array();
    }

    private static final class Peer implements AutoCloseable {
        final Path directory;
        final Path socket;
        final ServerSocketChannel listener;
        final Thread owner;
        final AtomicInteger connections = new AtomicInteger();
        final AtomicInteger frames = new AtomicInteger();
        final CompletableFuture<ProxyRequest> received = new CompletableFuture<>();
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch responseWritten = new CountDownLatch(1);
        volatile SocketChannel channel;
        volatile boolean closed;

        Peer(String mode, byte[] response) throws Exception {
            directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-local-rpc-");
            socket = directory.resolve("s");
            listener = ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX);
            listener.bind(java.net.UnixDomainSocketAddress.of(socket));
            listener.configureBlocking(false);
            owner = Thread.ofPlatform().daemon().start(() -> {
                try {
                    SocketChannel first = null;
                    while (first == null && !closed) {
                        first = listener.accept();
                        if (first == null) {
                            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(2));
                        }
                    }
                    if (first == null) {
                        return;
                    }
                    try (var accepted = first) {
                        channel = accepted;
                        connections.incrementAndGet();
                        if (mode.equals("no-read")) {
                            release.await();
                            return;
                        }
                        ProxyRequest request = FrameCodec.readRequest(Channels.newInputStream(accepted));
                        frames.incrementAndGet();
                        received.complete(request);
                        if (mode.equals("stall")) {
                            release.await();
                        } else if (mode.equals("drip")) {
                            for (byte value : response) {
                                Channels.newOutputStream(accepted).write(value);
                                Thread.sleep(150);
                            }
                        } else {
                            Channels.newOutputStream(accepted).write(response);
                            responseWritten.countDown();
                            if (mode.equals("no-eof")) {
                                release.await();
                            }
                        }
                    }
                } catch (Exception expectedAbort) {
                    received.completeExceptionally(expectedAbort);
                }
            });
        }

        int totalConnections() throws IOException {
            SocketChannel queued;
            while ((queued = listener.accept()) != null) {
                connections.incrementAndGet();
                queued.close();
            }
            return connections.get();
        }

        @Override
        public void close() throws Exception {
            closed = true;
            listener.close();
            SocketChannel accepted = channel;
            if (accepted != null) {
                accepted.close();
            }
            release.countDown();
            owner.join(1500);
            assertFalse(owner.isAlive());
            Files.deleteIfExists(socket);
            Files.delete(directory);
        }
    }
}
