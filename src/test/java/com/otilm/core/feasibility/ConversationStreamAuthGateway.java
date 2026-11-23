package com.otilm.core.feasibility;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.security.authn.ForwardedCertificateFixtures;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/** Synthetic credential binding before the existing genuine-policy fixture; never an Auth replacement. */
public final class ConversationStreamAuthGateway implements AutoCloseable {
    private static final int MAX_BODY = 65536;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] ANONYMOUS = "{\"authenticated\":false}".getBytes(StandardCharsets.UTF_8);
    private final HttpServer server;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
    private final URI upstream;
    private final UUID actor;
    private final AtomicInteger certificates = new AtomicInteger();
    private final AtomicInteger authoritative = new AtomicInteger();
    private final AtomicInteger denied = new AtomicInteger();

    public ConversationStreamAuthGateway(URI upstream, UUID actor) throws IOException {
        if (!"127.0.0.1".equals(upstream.getHost())) {
            throw new IllegalArgumentException("Loopback authority required");
        }
        this.upstream = upstream.resolve("/auth");
        this.actor = actor;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/auth", this::handle);
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public void reset() {
        certificates.set(0);
        authoritative.set(0);
        denied.set(0);
    }

    public int certificateRequests() {
        return certificates.get();
    }

    public int authoritativeRequests() {
        return authoritative.get();
    }

    public int deniedRequests() {
        return denied.get();
    }

    private void handle(HttpExchange exchange) throws IOException {
        int status = 200;
        byte[] response = ANONYMOUS;
        try {
            byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY + 1);
            if (!"POST".equals(exchange.getRequestMethod()) || !"/auth".equals(exchange.getRequestURI().getPath())
                    || body.length > MAX_BODY) {
                status = 400;
            } else {
                JsonNode request = JSON.readTree(body);
                boolean certificate = ForwardedCertificateFixtures.LEAF_DER
                        .equals(request.path("certificateContent").asText()) && absent(request, "userUuid")
                        && absent(request, "systemUsername") && absent(request, "authenticationTokenUserClaims");
                boolean user = actor.toString().equals(request.path("userUuid").asText())
                        && absent(request, "certificateContent") && absent(request, "systemUsername")
                        && absent(request, "authenticationTokenUserClaims");
                if (certificate || user) {
                    if (certificate) {
                        certificates.incrementAndGet();
                    } else {
                        authoritative.incrementAndGet();
                    }
                    var reply = client
                            .send(HttpRequest
                                    .newBuilder(upstream)
                                    .timeout(Duration.ofSeconds(5))
                                    .header("Content-Type", "application/json")
                                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                                    .build(), HttpResponse.BodyHandlers.ofByteArray());
                    status = reply.statusCode();
                    if (reply.body().length > MAX_BODY) {
                        status = 503;
                    } else {
                        response = reply.body();
                    }
                } else {
                    denied.incrementAndGet();
                }
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            status = 503;
        } catch (IOException | RuntimeException failure) {
            status = 503;
        }
        try {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, response.length);
            exchange.getResponseBody().write(response);
        } finally {
            exchange.close();
        }
    }

    private static boolean absent(JsonNode node, String field) {
        return node.path(field).isMissingNode() || node.path(field).isNull();
    }

    @Override
    public void close() {
        server.stop(0);
        client.close();
    }
}
