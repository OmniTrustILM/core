package com.otilm.ai.gateway;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;

/** Independent real socket oracle: progress inside idle timeout, finite eight-second fixture stop. */
final class SlowProgressFixture implements AutoCloseable {
    enum Phase {
        TLS,
        HEADERS,
        BODY
    }

    final AtomicBoolean clientHelloObserved = new AtomicBoolean();
    final AtomicReference<byte[]> completePost = new AtomicReference<>();
    final AtomicInteger progressBytes = new AtomicInteger();
    final AtomicBoolean clientClosed = new AtomicBoolean();
    final AtomicBoolean fixtureLimitReached = new AtomicBoolean();
    final AtomicReference<Throwable> failure = new AtomicReference<>();
    final CountDownLatch finished = new CountDownLatch(1);
    final CountDownLatch postObserved = new CountDownLatch(1);
    private final CountDownLatch stop = new CountDownLatch(1);
    private final java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(2);
    private final ServerSocket listener;
    private final HttpsFixture ca;
    private volatile Socket accepted;

    SlowProgressFixture(HttpsFixture ca, Phase phase) throws Exception {
        this.ca = ca;
        listener = new ServerSocket(0, 1, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        listener.setSoTimeout(3000);
        workers.submit(() -> serve(phase));
    }

    private void serve(Phase phase) {
        try (Socket raw = listener.accept()) {
            accepted = raw;
            raw.setSoTimeout(12000);
            Socket wire = raw;
            if (phase != Phase.TLS) {
                SSLSocket tls = (SSLSocket) ca.serverTls
                        .getSocketFactory()
                        .createSocket(raw, "provider.invalid", raw.getPort(), true);
                tls.setUseClientMode(false);
                tls.startHandshake();
                wire = tls;
                readCompletePost(tls);
                String response = phase == Phase.HEADERS
                        ? "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Slow: "
                        : "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8192\r\n\r\n";
                tls.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
            } else {
                byte[] header = raw.getInputStream().readNBytes(5);
                if (header.length != 5 || header[0] != 22) {
                    throw new AssertionError("Missing ClientHello record");
                }
                int length = ((header[3] & 255) << 8) | (header[4] & 255);
                if (length < 1 || length > 32768 || raw.getInputStream().readNBytes(length).length != length) {
                    throw new AssertionError("Incomplete ClientHello record");
                }
                clientHelloObserved.set(true);
                // A valid-size TLS record whose body deliberately remains incomplete.
                raw.getOutputStream().write(new byte[]{22, 3, 3, 16, 0});
            }
            Socket monitored = wire;
            workers.submit(() -> observePeerClose(monitored));
            long started = System.nanoTime();
            while (!clientClosed.get() && stop.getCount() != 0) {
                if (System.nanoTime() - started >= TimeUnit.SECONDS.toNanos(8)) {
                    fixtureLimitReached.set(true);
                    break;
                }
                try {
                    wire.getOutputStream().write('a');
                    wire.getOutputStream().flush();
                    progressBytes.incrementAndGet();
                } catch (IOException closed) {
                    if (stop.getCount() != 0 && !fixtureLimitReached.get()) {
                        clientClosed.set(true);
                    }
                    break;
                }
                if (stop.await(75, TimeUnit.MILLISECONDS)) {
                    break;
                }
            }
            wire.close();
        } catch (Exception | AssertionError problem) {
            if (stop.getCount() != 0) {
                failure.set(problem);
            }
        } finally {
            finished.countDown();
        }
    }

    private void observePeerClose(Socket wire) {
        try {
            while (wire.getInputStream().read() >= 0) {
                /* discard TLS control bytes only */ }
            if (stop.getCount() != 0 && !fixtureLimitReached.get()) {
                clientClosed.set(true);
            }
        } catch (IOException closed) {
            if (stop.getCount() != 0 && !fixtureLimitReached.get()) {
                clientClosed.set(true);
            }
        }
    }

    private void readCompletePost(SSLSocket tls) throws Exception {
        var input = tls.getInputStream();
        var headers = new ByteArrayOutputStream();
        int ending = 0;
        while (headers.size() < 32768 && ending != 0x0d0a0d0a) {
            int value = input.read();
            if (value < 0) {
                throw new AssertionError("Incomplete POST headers");
            }
            headers.write(value);
            ending = (ending << 8) | value;
        }
        String text = headers.toString(StandardCharsets.ISO_8859_1);
        if (!text.startsWith("POST /v1/chat/completions HTTP/1.1\r\n")) {
            throw new AssertionError("Wrong POST route");
        }
        var match = Pattern.compile("(?im)^Content-Length: ([0-9]+)\\r?$").matcher(text);
        if (!match.find()) {
            throw new AssertionError("Missing POST length");
        }
        int length = Integer.parseInt(match.group(1));
        if (length < 1 || length > 1048576) {
            throw new AssertionError("Unbounded POST length");
        }
        byte[] body = input.readNBytes(length);
        if (body.length != length) {
            throw new AssertionError("Incomplete POST body");
        }
        completePost.set(body);
        postObserved.countDown();
    }

    PinnedEndpoint endpoint() {
        var original = ca.endpoint();
        return new PinnedEndpoint(URI.create("https://provider.invalid:" + listener.getLocalPort()),
                original.addresses(), original.trust());
    }

    @Override
    public void close() throws Exception {
        stop.countDown();
        listener.close();
        Socket socket = accepted;
        if (socket != null) {
            socket.close();
        }
        workers.shutdownNow();
        if (!workers.awaitTermination(3, TimeUnit.SECONDS)) {
            throw new AssertionError("Owned drip workers survived");
        }
    }
}
