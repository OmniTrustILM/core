package com.otilm.ai.runner;

import com.otilm.ai.proxy.FrameCodec;
import com.otilm.ai.proxy.ProxyReply;
import com.otilm.ai.proxy.ProxyRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/** One bounded pathname-UDS exchange. A parsed reply grants no Core authority and never triggers a retry. */
public final class LocalRpcClient {
    private static final long MAX_NANOS = TimeUnit.SECONDS.toNanos(8);
    private static final int MAX_REPLY_BYTES = 28 + FrameCodec.MAX_PAYLOAD_BYTES;
    private final Path socket;

    public LocalRpcClient(Path socket) {
        if (socket == null || !socket.isAbsolute() || !socket.equals(socket.normalize())
                || socket.getParent() == null) {
            throw new IllegalArgumentException("LOCAL_RPC_FAILED");
        }
        this.socket = socket;
    }

    public ProxyReply exchange(ProxyRequest request, long availableNanos) throws IOException {
        long started = System.nanoTime();
        long budget = Math.min(MAX_NANOS, availableNanos);
        try {
            remaining(started, budget);
            var encoded = new ByteArrayOutputStream();
            FrameCodec.writeRequest(encoded, request);
            ByteBuffer output = ByteBuffer.wrap(encoded.toByteArray());
            try (var selector = Selector.open(); var channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                channel.configureBlocking(false);
                var key = channel.register(selector, 0);
                remaining(started, budget);
                connect(channel, selector, key, started, budget);
                writeRequest(channel, selector, key, output, started, budget);
                remaining(started, budget);
                channel.shutdownOutput();
                return readReply(channel, selector, key, request, started, budget);
            }
        } catch (IOException | RuntimeException unavailable) {
            throw new IOException("LOCAL_RPC_FAILED");
        }
    }

    private void connect(SocketChannel channel, Selector selector, SelectionKey key, long started, long budget)
            throws IOException {
        if (!channel.connect(UnixDomainSocketAddress.of(socket))) {
            while (true) {
                remaining(started, budget);
                if (channel.finishConnect()) {
                    break;
                }
                await(selector, key, SelectionKey.OP_CONNECT, started, budget);
            }
        }
    }

    private static void writeRequest(SocketChannel channel, Selector selector, SelectionKey key, ByteBuffer output,
            long started, long budget) throws IOException {
        while (output.hasRemaining()) {
            remaining(started, budget);
            if (channel.write(output) == 0) {
                await(selector, key, SelectionKey.OP_WRITE, started, budget);
            }
        }
    }

    private static ProxyReply readReply(SocketChannel channel, Selector selector, SelectionKey key,
            ProxyRequest request, long started, long budget) throws IOException {
        ByteBuffer input = ByteBuffer.allocate(MAX_REPLY_BYTES + 1);
        while (true) {
            remaining(started, budget);
            int count = channel.read(input);
            if (count < 0) {
                break;
            }
            if (input.position() > MAX_REPLY_BYTES) {
                throw new IOException("LOCAL_RPC_FAILED");
            }
            if (count == 0) {
                await(selector, key, SelectionKey.OP_READ, started, budget);
            }
        }
        remaining(started, budget);
        ProxyReply reply = FrameCodec
                .readReply(new ByteArrayInputStream(Arrays.copyOf(input.array(), input.position())));
        remaining(started, budget);
        if (!request.correlationId().equals(reply.correlationId())) {
            throw new IOException("LOCAL_RPC_FAILED");
        }
        return reply;
    }

    private static void await(Selector selector, SelectionKey key, int operation, long started, long budget)
            throws IOException {
        key.interestOps(operation);
        long available = remaining(started, budget);
        selector.select(Math.max(1, (available + 999_999) / 1_000_000));
        selector.selectedKeys().clear();
        remaining(started, budget);
    }

    private static long remaining(long started, long budget) throws IOException {
        if (budget <= 0) {
            throw new IOException("LOCAL_RPC_FAILED");
        }
        long available = budget - (System.nanoTime() - started);
        if (available <= 0 || Thread.currentThread().isInterrupted()) {
            throw new IOException("LOCAL_RPC_FAILED");
        }
        return available;
    }
}
