package com.otilm.ai.gateway;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;

// Independent hostile test server: read a complete real POST, then inject an invalid encrypted TLS record.
final class PostSendTlsFaultFixture implements AutoCloseable {
    final AtomicReference<byte[]> received = new AtomicReference<>();
    final AtomicBoolean faultInjected = new AtomicBoolean();
    final AtomicReference<Throwable> fixtureFailure = new AtomicReference<>();
    final CountDownLatch finished = new CountDownLatch(1);
    private final java.util.concurrent.ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ServerSocket listener;
    private final HttpsFixture ca;

    PostSendTlsFaultFixture(HttpsFixture ca) throws Exception {
        this.ca = ca;
        listener = new ServerSocket(0, 1, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        listener.setSoTimeout(3000);
        executor.submit(() -> {
            try (var socket = listener.accept();
                    var tls = (SSLSocket) ca.serverTls
                            .getSocketFactory()
                            .createSocket(socket, "provider.invalid", socket.getPort(), false)) {
                socket.setSoTimeout(3000);
                tls.setUseClientMode(false);
                tls.startHandshake();
                var input = tls.getInputStream();
                var headers = new ByteArrayOutputStream();
                int ending = 0;
                while (headers.size() < 32768 && ending != 0x0d0a0d0a) {
                    int value = input.read();
                    if (value < 0) {
                        throw new AssertionError("Missing complete synthetic POST headers");
                    }
                    headers.write(value);
                    ending = (ending << 8) | value;
                }
                String text = headers.toString(StandardCharsets.ISO_8859_1);
                if (!text.startsWith("POST /v1/chat/completions HTTP/1.1\r\n")) {
                    throw new AssertionError("Unexpected fixed request path");
                }
                var length = Pattern.compile("(?im)^Content-Length: ([0-9]+)\\r?$").matcher(text);
                if (!length.find()) {
                    throw new AssertionError("Missing synthetic request length");
                }
                int count = Integer.parseInt(length.group(1));
                if (count < 1 || count > 1048576) {
                    throw new AssertionError("Unexpected synthetic request size");
                }
                byte[] body = input.readNBytes(count);
                if (body.length != count) {
                    throw new AssertionError("Incomplete synthetic POST");
                }
                received.set(body);
                socket.getOutputStream().write(new byte[]{23, 3, 3, 0, 1, 0});
                socket.getOutputStream().flush();
                faultInjected.set(true);
            } catch (Exception | AssertionError failure) {
                fixtureFailure.set(failure);
            } finally {
                finished.countDown();
            }
        });
    }

    PinnedEndpoint endpoint() {
        var original = ca.endpoint();
        return new PinnedEndpoint(URI.create("https://provider.invalid:" + listener.getLocalPort()),
                original.addresses(), original.trust());
    }

    @Override
    public void close() throws Exception {
        listener.close();
        executor.shutdownNow();
        if (!executor.awaitTermination(4, TimeUnit.SECONDS)) {
            throw new AssertionError("Owned TLS fault fixture did not stop");
        }
    }
}
