package com.otilm.ai.runner;

import com.otilm.ai.proxy.FrameCodec;
import com.otilm.ai.proxy.LocalOperation;
import com.otilm.ai.proxy.ProxyReply;
import com.otilm.ai.proxy.ProxyRequest;
import com.otilm.ai.runtime.protocol.BootstrapClaimedReply;
import com.otilm.ai.runtime.protocol.BootstrapPendingReply;
import com.otilm.ai.runtime.protocol.ClaimBinding;
import com.otilm.ai.runtime.protocol.ClaimHeartbeatReply;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(10)
class RunnerBootstrapTest {
    static final UUID RUN = UUID.fromString("00000000-0000-4000-8000-000000000001");
    static final UUID ATTEMPT = UUID.fromString("00000000-0000-4000-8000-000000000002");
    static final UUID POD = UUID.fromString("00000000-0000-4000-8000-000000000003");
    static final UUID CLAIM = UUID.fromString("00000000-0000-4000-8000-000000000004");
    static final ClaimBinding BINDING = new ClaimBinding(RUN, ATTEMPT, POD, CLAIM, 7);
    static final ProtocolCodec CODEC = new ProtocolCodec();

    @Test
    void onlyDefinitivePendingCanLeadToAnotherBootstrapThenOneExactHeartbeat() throws Exception {
        try (var peer = new Peer("pending-then-claimed")) {
            assertTrue(new RunnerBootstrap(new LocalRpcClient(peer.socket)).run(RUN, ATTEMPT, POD, System.nanoTime()));
            peer.awaitFrames(3);
            assertEquals(List.of(LocalOperation.BOOTSTRAP, LocalOperation.BOOTSTRAP, LocalOperation.HEARTBEAT),
                    peer.frames.stream().map(ProxyRequest::operation).toList());
            assertEquals(2, peer.frames.stream().limit(2).map(ProxyRequest::correlationId).distinct().count());
            for (ProxyRequest frame : peer.frames.subList(0, 2)) {
                var request = CODEC.readBootstrapRequest(frame.payload());
                assertEquals(RUN, request.runId());
                assertEquals(ATTEMPT, request.attemptId());
                assertEquals(POD, request.podUid());
            }
            var heartbeat = CODEC.readClaimHeartbeatRequest(peer.frames.get(2).payload());
            assertEquals(BINDING, heartbeat.binding());
            assertEquals(1, heartbeat.sequence());
        }
    }

    @Test
    void elevenPendingRepliesExhaustTheFiniteProtocolRetryLimitWithoutAHeartbeat() throws Exception {
        try (var peer = new Peer("always-pending")) {
            assertFalse(new RunnerBootstrap(new LocalRpcClient(peer.socket)).run(RUN, ATTEMPT, POD, System.nanoTime()));
            peer.awaitFrames(11);
            assertEquals(11, peer.frames.size());
            assertTrue(peer.frames.stream().allMatch(frame -> frame.operation() == LocalOperation.BOOTSTRAP));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "unknown",
            "not-sent",
            "201",
            "202",
            "302",
            "401",
            "408",
            "421",
            "500",
            "503",
            "bad-body",
            "wrong-correlation",
            "wrong-run",
            "wrong-attempt",
            "wrong-pod",
            "expired-claim"})
    void uncertainErrorOrWrongClaimNeverSendsAnotherFrame(String mode) throws Exception {
        try (var peer = new Peer(mode)) {
            assertFalse(new RunnerBootstrap(new LocalRpcClient(peer.socket)).run(RUN, ATTEMPT, POD, System.nanoTime()));
            peer.awaitFrames(1);
            assertEquals(1, peer.frames.size());
            assertEquals(LocalOperation.BOOTSTRAP, peer.frames.getFirst().operation());
        }
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"wrong-heartbeat-binding", "wrong-heartbeat-sequence", "expired-heartbeat", "heartbeat-503"})
    void aHeartbeatFailureDoesNotSendASecondHeartbeat(String mode) throws Exception {
        try (var peer = new Peer(mode)) {
            assertFalse(new RunnerBootstrap(new LocalRpcClient(peer.socket)).run(RUN, ATTEMPT, POD, System.nanoTime()));
            peer.awaitFrames(2);
            assertEquals(2, peer.frames.size());
            assertEquals(LocalOperation.HEARTBEAT, peer.frames.get(1).operation());
        }
    }

    @Test
    void anExpiredMainBudgetDoesNotConnect() throws Exception {
        try (var peer = new Peer("claimed")) {
            assertFalse(new RunnerBootstrap(new LocalRpcClient(peer.socket))
                    .run(RUN, ATTEMPT, POD, System.nanoTime() - TimeUnit.SECONDS.toNanos(110)));
            assertEquals(0, peer.frames.size());
        }
    }

    static final class Peer implements AutoCloseable {
        final Path directory;
        final Path socket;
        final ServerSocketChannel listener;
        final List<ProxyRequest> frames = new CopyOnWriteArrayList<>();
        final List<SocketChannel> connections = new CopyOnWriteArrayList<>();
        final Thread thread;
        final String mode;
        volatile boolean closed;

        Peer(String mode) throws Exception {
            this.mode = mode;
            directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-flow-");
            socket = directory.resolve("s");
            listener = ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX);
            listener.bind(java.net.UnixDomainSocketAddress.of(socket));
            thread = Thread.ofPlatform().daemon().start(this::serve);
        }

        void serve() {
            while (!closed) {
                try (var connection = listener.accept()) {
                    connections.add(connection);
                    ProxyRequest request = FrameCodec.readRequest(Channels.newInputStream(connection));
                    frames.add(request);
                    ProxyReply reply = response(request);
                    FrameCodec.writeReply(Channels.newOutputStream(connection), reply);
                } catch (Exception expectedClosure) {
                    if (!closed) {
                        throw new AssertionError("SYNTHETIC_PEER_FAILED");
                    }
                }
            }
        }

        ProxyReply response(ProxyRequest request) {
            var id = mode.equals("wrong-correlation") ? UUID.randomUUID() : request.correlationId();
            if (mode.equals("unknown") || mode.equals("not-sent")) {
                return new ProxyReply(mode.equals("unknown") ? ProxyReply.Outcome.UNKNOWN : ProxyReply.Outcome.NOT_SENT,
                        id, 0, new byte[0]);
            }
            int status = mode.matches("\\d{3}") ? Integer.parseInt(mode) : 200;
            byte[] body;
            if (request.operation() == LocalOperation.BOOTSTRAP) {
                if (mode.equals("always-pending") || (mode.equals("pending-then-claimed") && frames.size() == 1)
                        || status != 200) {
                    body = CODEC.writeBootstrapReply(new BootstrapPendingReply(1, 100));
                } else if (mode.equals("bad-body")) {
                    body = "{\"PRIVATE_BODY_CANARY\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                } else {
                    var binding = new ClaimBinding(mode.equals("wrong-run") ? CLAIM : RUN,
                            mode.equals("wrong-attempt") ? CLAIM : ATTEMPT, mode.equals("wrong-pod") ? CLAIM : POD,
                            CLAIM, 7);
                    body = CODEC
                            .writeBootstrapReply(new BootstrapClaimedReply(1, binding,
                                    mode.equals("expired-claim") ? Instant.EPOCH : Instant.now().plusSeconds(30)));
                }
            } else {
                var binding = mode.equals("wrong-heartbeat-binding")
                        ? new ClaimBinding(RUN, ATTEMPT, POD, CLAIM, 8)
                        : BINDING;
                body = CODEC
                        .writeClaimHeartbeatReply(new ClaimHeartbeatReply(1, binding,
                                mode.equals("wrong-heartbeat-sequence") ? 2 : 1,
                                mode.equals("expired-heartbeat") ? Instant.EPOCH : Instant.now().plusSeconds(30)));
                if (mode.equals("heartbeat-503")) {
                    status = 503;
                }
            }
            return new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, id, status, body);
        }

        void awaitFrames(int count) throws Exception {
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (frames.size() < count && System.nanoTime() < until) {
                Thread.sleep(5);
            }
            assertEquals(count, frames.size());
        }

        @Override
        public void close() throws Exception {
            closed = true;
            listener.close();
            for (SocketChannel connection : connections) {
                connection.close();
            }
            thread.join(1000);
            assertFalse(thread.isAlive());
            Files.deleteIfExists(socket);
            Files.delete(directory);
        }
    }
}
