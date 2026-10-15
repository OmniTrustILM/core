package com.otilm.core.config.http;

import com.otilm.core.util.LoopbackWireMock;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

/**
 * Guards the request-factory defaults every platform {@code RestClient} inherits. A bare
 * {@code ClientHttpRequestFactoryBuilder.detect()} fails each of these.
 */
class PlatformHttpClientsTest {

    private static final int CONCURRENT_REQUESTS = 40;

    private HttpServer server;
    private ExecutorService serverExecutor;
    private String url;
    private final AtomicInteger requestCount = new AtomicInteger();
    private volatile List<String> lastCookieHeader;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(LoopbackWireMock.HOST, 0), 0);
        serverExecutor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(serverExecutor);
        url = LoopbackWireMock.url(server.getAddress().getPort()) + "/probe";
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
        // HttpServer.stop() leaves an executor supplied via setExecutor running.
        serverExecutor.shutdownNow();
    }

    private RestClient client() {
        return client(null);
    }

    private RestClient client(HttpClientSettings settings) {
        return RestClient.builder().requestFactory(PlatformHttpClients.requestFactoryBuilder().build(settings)).build();
    }

    private void respond(HttpExchange exchange, int status, String cookie) throws IOException {
        requestCount.incrementAndGet();
        lastCookieHeader = exchange.getRequestHeaders().get("Cookie");
        if (cookie != null) {
            exchange.getResponseHeaders().add("Set-Cookie", cookie);
        }
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    @Test
    void testPoolAllowsMoreConcurrencyThanApacheDefault() throws Exception {
        CountDownLatch arrived = new CountDownLatch(CONCURRENT_REQUESTS);
        server.createContext("/probe", exchange -> {
            arrived.countDown();
            try {
                arrived.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(exchange, 200, null);
        });
        server.start();

        RestClient client = client();
        ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_REQUESTS);
        try {
            List<Future<?>> calls = new ArrayList<>();
            for (int i = 0; i < CONCURRENT_REQUESTS; i++) {
                calls.add(executor.submit(() -> client.get().uri(url).retrieve().toBodilessEntity()));
            }

            Assertions
                    .assertTrue(arrived.await(5, TimeUnit.SECONDS),
                            "connection pool held concurrency below " + CONCURRENT_REQUESTS + " simultaneous requests");
            for (Future<?> call : calls) {
                Assertions.assertNotNull(call.get(10, TimeUnit.SECONDS));
            }
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void testFailsFastWhenPoolIsExhausted() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch occupied = new CountDownLatch(PlatformHttpClients.MAX_CONNECTIONS);
        server.createContext("/probe", exchange -> {
            occupied.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(exchange, 200, null);
        });
        server.start();

        RestClient client = client();
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        try {
            for (int i = 0; i < PlatformHttpClients.MAX_CONNECTIONS; i++) {
                executor.submit(() -> client.get().uri(url).retrieve().toBodilessEntity());
            }
            Assertions.assertTrue(occupied.await(20, TimeUnit.SECONDS), "pool never reached its configured ceiling");

            RestClient.ResponseSpec shedCall = client.get().uri(url).retrieve();
            long startedAt = System.nanoTime();
            Assertions.assertThrows(ResourceAccessException.class, shedCall::toBodilessEntity);
            Duration waited = Duration.ofNanos(System.nanoTime() - startedAt);

            Assertions
                    .assertTrue(waited.toSeconds() < 60,
                            "caller waited " + waited + " for a connection, so no lease timeout is configured");
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void testKeepsConsumerSuppliedReadTimeout() {
        CountDownLatch release = new CountDownLatch(1);
        server.createContext("/probe", exchange -> {
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(exchange, 200, null);
        });
        server.start();

        RestClient client = client(HttpClientSettings
                .defaults()
                .withConnectTimeout(Duration.ofSeconds(5))
                .withReadTimeout(Duration.ofMillis(300)));
        try {
            RestClient.ResponseSpec timingOutCall = client.get().uri(url).retrieve();
            long startedAt = System.nanoTime();
            Assertions.assertThrows(ResourceAccessException.class, timingOutCall::toBodilessEntity);
            Duration waited = Duration.ofNanos(System.nanoTime() - startedAt);

            Assertions
                    .assertTrue(waited.compareTo(Duration.ofSeconds(3)) < 0, "call failed only after " + waited
                            + ", so the 300ms read timeout it was given was overwritten");
        } finally {
            release.countDown();
        }
    }

    @Test
    void testDoesNotReplayCookies() {
        server.createContext("/probe", exchange -> respond(exchange, 200, "SESSION=first-caller; Path=/"));
        server.start();

        RestClient client = client();
        client.get().uri(url).retrieve().toBodilessEntity();
        client.get().uri(url).retrieve().toBodilessEntity();

        Assertions.assertEquals(2, requestCount.get());
        Assertions.assertNull(lastCookieHeader, "second request carried a cookie from the first response");
    }

    @Test
    void testDoesNotRetryOnServiceUnavailable() {
        server.createContext("/probe", exchange -> {
            exchange.getResponseHeaders().add("Retry-After", "30");
            respond(exchange, 503, null);
        });
        server.start();

        RestClient.ResponseSpec response = client().get().uri(url).retrieve();
        Assertions.assertThrows(HttpServerErrorException.class, response::toBodilessEntity);

        Assertions.assertEquals(1, requestCount.get());
    }

    @Test
    void testRetriesOnceAfterConnectionFailure() {
        server.createContext("/probe", exchange -> {
            if (requestCount.incrementAndGet() == 1) {
                exchange.close();
                return;
            }
            byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        Assertions.assertEquals(200, client().get().uri(url).retrieve().toBodilessEntity().getStatusCode().value());
        Assertions.assertEquals(2, requestCount.get());
    }
}
