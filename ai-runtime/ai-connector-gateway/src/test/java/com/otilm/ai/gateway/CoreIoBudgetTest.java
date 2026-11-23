package com.otilm.ai.gateway;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Actual socket closure controls; no Core authorization or native runtime admission proof. */
class CoreIoBudgetTest {
    @TempDir
    Path directory;

    @Test
    void hugeDeclaredCoreBodyIsClosedWithoutWaitingForOrDrainingItsAbsentBytes() throws Exception {
        try (var f = new GatewayRunFixture(directory); var peer = new Peer(f, true)) {
            configure(f, peer);
            Files.delete(f.secret);
            long started = System.nanoTime();
            assertThrows(GatewayFailure.class, () -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL));
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2));
            assertTrue(peer.closed.await(1, TimeUnit.SECONDS));
            assertEquals(1, peer.requests.get());
            assertNull(peer.failure.get());
            assertEquals(0, f.consumes.get());
            assertEquals(0, f.sends.get());
            assertEquals(0, f.outcomes.get());
        }
    }

    @Test
    void theSameOperationWatchdogClosesAnActualStalledCoreTlsHandshake() throws Exception {
        try (var f = new GatewayRunFixture(directory); var peer = new Peer(f, false)) {
            configure(f, peer);
            Files.delete(f.secret);
            var transport = new ChatCompletionsTransport(Duration.ofSeconds(1), Duration.ofSeconds(1),
                    Thread.ofPlatform().daemon().factory());
            long started = System.nanoTime();
            assertThrows(GatewayFailure.class,
                    () -> GatewayRun.execute(f.envelope, f.config, transport, GatewayRunWireTest.CALL));
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2));
            assertTrue(peer.closed.await(1, TimeUnit.SECONDS));
            assertTrue(peer.helloBytes.get() > 0);
            assertNull(peer.failure.get());
            assertEquals(0, f.consumes.get());
            assertEquals(0, f.sends.get());
            assertEquals(0, f.outcomes.get());
        }
    }

    private static void configure(GatewayRunFixture f, Peer p) throws Exception {
        var config = (com.fasterxml.jackson.databind.node.ObjectNode) GatewayRunWireTest.JSON
                .readTree(Files.readAllBytes(f.config));
        config.put("coreOrigin", "https://core.test:" + p.listener.getLocalPort());
        Files.write(f.config, GatewayRunWireTest.JSON.writeValueAsBytes(config));
    }

    private static final class Peer implements AutoCloseable {
        final ServerSocket listener;
        final Thread owner;
        final AtomicInteger requests = new AtomicInteger(), helloBytes = new AtomicInteger();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final CountDownLatch closed = new CountDownLatch(1);
        volatile Socket socket;

        Peer(GatewayRunFixture fixture, boolean headers) throws Exception {
            listener = headers
                    ? fixture.coreServerTls
                            .getServerSocketFactory()
                            .createServerSocket(0, 8, InetAddress.getLoopbackAddress())
                    : new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
            if (listener instanceof SSLServerSocket tls) {
                tls.setNeedClientAuth(true);
                tls.setEnabledProtocols(new String[]{"TLSv1.3"});
            }
            owner = Thread.ofPlatform().daemon().start(() -> serve(headers));
        }

        private void serve(boolean headers) {
            boolean awaitingClose = false;
            try (var peer = listener.accept()) {
                socket = peer;
                peer.setSoTimeout(3500);
                var input = peer.getInputStream();
                if (headers) {
                    ((SSLSocket) peer).startHandshake();
                    var buffer = new ByteArrayOutputStream();
                    int match = 0;
                    while (match < 4) {
                        int next = input.read();
                        if (next < 0 || buffer.size() > 16384) {
                            throw new IOException("FIXTURE_REQUEST");
                        }
                        buffer.write(next);
                        match = next == "\r\n\r\n".charAt(match) ? match + 1 : (next == '\r' ? 1 : 0);
                    }
                    int length = -1;
                    for (String line : buffer.toString(StandardCharsets.ISO_8859_1).split("\r\n")) {
                        if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                            length = Integer.parseInt(line.substring(15).trim());
                        }
                    }
                    String request = buffer.toString(StandardCharsets.ISO_8859_1);
                    if (!request.startsWith("GET " + GatewayRun.Audience.RUN.registrationPath() + " HTTP/1.1\r\n")
                            || length > 0
                            || java.util.Arrays
                                    .stream(request.split("\r\n"))
                                    .skip(1)
                                    .map(line -> line.toLowerCase(java.util.Locale.ROOT))
                                    .anyMatch(line -> line.startsWith("transfer-encoding:")
                                            || line.startsWith("content-type:") || line.startsWith("authorization:")
                                            || line.startsWith("cookie:") || line.startsWith("cookie2:"))) {
                        throw new IOException("FIXTURE_REGISTRATION_GET");
                    }
                    requests.incrementAndGet();
                    peer
                            .getOutputStream()
                            .write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1500001\r\nConnection: close\r\n\r\n"
                                    .getBytes(StandardCharsets.US_ASCII));
                    peer.getOutputStream().flush();
                    awaitingClose = true;
                } else {
                    if (input.read() < 0) {
                        throw new IOException("FIXTURE_HELLO");
                    }
                    helloBytes.incrementAndGet();
                    awaitingClose = true;
                }
                while (input.read() != -1) {
                    if (!headers) {
                        helloBytes.incrementAndGet();
                    }
                }
                closed.countDown();
            } catch (java.net.SocketTimeoutException timeout) {
                failure.set(timeout);
            } catch (IOException expectedAbort) {
                if (awaitingClose) {
                    closed.countDown();
                } else {
                    failure.set(expectedAbort);
                }
            } catch (RuntimeException unexpected) {
                failure.set(unexpected);
            }
        }

        @Override
        public void close() throws Exception {
            listener.close();
            var peer = socket;
            if (peer != null) {
                peer.close();
            }
            owner.join(2000);
            assertFalse(owner.isAlive());
        }
    }
}
