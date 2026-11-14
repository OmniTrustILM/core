package com.otilm.ai.proxy;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.impl.io.DefaultBHttpClientConnection;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SingleAttemptExecutorTest {
    @Test
    void rejectsASecondAttemptBeforeAnySecondHeaderOrBodyReachesTheWire() throws Exception {
        AtomicInteger received = new AtomicInteger();
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> peer = CompletableFuture.runAsync(() -> {
                try (Socket socket = server.accept()) {
                    socket.setSoTimeout(2000);
                    var input = socket.getInputStream();
                    while (true) {
                        int match = 0;
                        while (match < 4) {
                            int value = input.read();
                            if (value < 0) {
                                return;
                            }
                            match = value == "\r\n\r\n".charAt(match) ? match + 1 : (value == '\r' ? 1 : 0);
                        }
                        if (input.readNBytes(1).length != 1) {
                            return;
                        }
                        received.incrementAndGet();
                        socket
                                .getOutputStream()
                                .write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
                                        .getBytes(StandardCharsets.US_ASCII));
                        socket.getOutputStream().flush();
                    }
                } catch (Exception failure) {
                    throw new java.util.concurrent.CompletionException(failure);
                }
            });
            try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
                    var connection = new DefaultBHttpClientConnection(Http1Config.DEFAULT)) {
                connection.bind(socket);
                var executor = FixedCoreHttp.singleAttemptExecutor();
                var request = new BasicClassicHttpRequest("POST", "/fixed");
                request.setVersion(HttpVersion.HTTP_1_1);
                request.setHeader("Host", "core.test");
                request.setHeader("Content-Length", "1");
                request
                        .setEntity(new InputStreamEntity(new ByteArrayInputStream(new byte[]{42}), 1,
                                ContentType.APPLICATION_JSON));
                assertFalse(request.getEntity().isRepeatable());
                assertEquals(204, executor.execute(request, connection, null, HttpCoreContext.create()).getCode());
                request
                        .setEntity(new InputStreamEntity(new ByteArrayInputStream(new byte[]{43}), 1,
                                ContentType.APPLICATION_JSON));
                assertThrows(java.io.IOException.class,
                        () -> executor.execute(request, connection, null, HttpCoreContext.create()));
            }
            peer.get(3, TimeUnit.SECONDS);
            assertEquals(1, received.get());
        }
    }
}
