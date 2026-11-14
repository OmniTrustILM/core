package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.impl.io.DefaultBHttpClientConnection;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SingleAttemptUpgradeTest {
    @Test
    void rejectsAnUnsolicitedUpgradeBeforeHandingItToTheLibraryUpgradeCallback() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicInteger upgrades = new AtomicInteger();
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> peer = CompletableFuture.runAsync(() -> {
                try (Socket socket = server.accept()) {
                    socket.setSoTimeout(2000);
                    int match = 0;
                    while (match < 4) {
                        int value = socket.getInputStream().read();
                        if (value < 0) {
                            throw new AssertionError("truncated request");
                        }
                        match = value == "\r\n\r\n".charAt(match) ? match + 1 : (value == '\r' ? 1 : 0);
                    }
                    requests.incrementAndGet();
                    socket
                            .getOutputStream()
                            .write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: TLS/1.3\r\n\r\n"
                                    .getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().flush();
                } catch (Exception failure) {
                    throw new java.util.concurrent.CompletionException(failure);
                }
            });
            try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
                    var connection = new DefaultBHttpClientConnection(Http1Config.DEFAULT)) {
                connection.bind(socket);
                var request = new BasicClassicHttpRequest("POST", "/fixed");
                request.setVersion(HttpVersion.HTTP_1_1);
                request.setHeader("Host", "core.test");
                Exception rejection = assertThrows(Exception.class, () -> FixedCoreHttp
                        .singleAttemptExecutor()
                        .execute(request, connection, (response, current, context) -> upgrades.incrementAndGet(),
                                HttpCoreContext.create()));
                assertEquals(0, upgrades.get());
                assertInstanceOf(HttpException.class, rejection);
            }
            peer.get(3, TimeUnit.SECONDS);
            assertEquals(1, requests.get());
        }
    }
}
