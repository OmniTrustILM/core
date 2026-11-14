package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CoreRpcClientTest {
    @TempDir
    Path directory;

    @Test
    void fixedBootstrapRetainsTheAdministratorServletContext() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.requiredPath = "/api" + LocalOperation.BOOTSTRAP.path();
            var base = fixture.configuration();
            var configuration = org.junit.jupiter.api.Assertions
                    .assertDoesNotThrow(() -> new ProxyConfiguration(URI.create(base.coreOrigin() + "/api"),
                            base.coreAddress(), base.certificateFile(), base.privateKeyFile(), base.serverCaFile()));
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                    new CoreRpcClient(configuration).execute(WireBodies.bootstrap()).outcome());
            assertTrue(fixture.requestHeaders
                    .startsWith("POST /api/internal/ai-runtime/v1/runner/bootstrap HTTP/1.1\r\n"));
            assertEquals(1, fixture.requests.get());
        }
    }

    @Test
    void sendsOnlyFixedBootstrapPathBodyHostAndCurrentClientIdentity() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            ProxyReply reply = new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap());
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, reply.outcome());
            assertEquals(200, reply.httpStatus());
            assertArrayEquals(WireBodies.PENDING, reply.payload());
            assertEquals(WireBodies.CALL, reply.correlationId());
            assertEquals(1, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
            assertTrue(fixture.requestHeaders.startsWith("POST /internal/ai-runtime/v1/runner/bootstrap HTTP/1.1\r\n"));
            assertTrue(fixture.requestHeaders.contains("Host: core.test:" + fixture.listener.getLocalPort() + "\r\n"));
            assertTrue(fixture.requestHeaders.contains("Content-Type: application/json"));
            assertFalse(fixture.requestHeaders.toLowerCase().contains("authorization:"));
            assertFalse(fixture.requestHeaders.toLowerCase().contains("cookie:"));
            assertFalse(fixture.requestHeaders.toLowerCase().contains("accept-encoding:"));
            assertFalse(fixture.requestHeaders.toLowerCase().contains("upgrade:"));
            assertArrayEquals(WireBodies.BOOTSTRAP, fixture.requestBody);
            assertEquals(fixture.client.certificate().getSerialNumber(), fixture.peerSerial);
        }
    }

    @Test
    void usesOnlyHeartbeatContractAndAFreshConnectionForEachOperation() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.respond(200, "Set-Cookie: ignored=secret\r\n", WireBodies.HEARTBEAT_REPLY);
            CoreRpcClient client = new CoreRpcClient(fixture.configuration());
            var request = new ProxyRequest(LocalOperation.HEARTBEAT, WireBodies.CALL, WireBodies.HEARTBEAT);
            for (int i = 0; i < 2; i++) {
                assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, client.execute(request).outcome());
                assertTrue(fixture.requestHeaders
                        .startsWith("POST /internal/ai-runtime/v1/runner/claims/heartbeat HTTP/1.1\r\n"));
                assertArrayEquals(WireBodies.HEARTBEAT, fixture.requestBody);
                assertFalse(fixture.requestHeaders.toLowerCase().contains("cookie:"));
            }
            assertEquals(2, fixture.connections.get());
            assertEquals(2, fixture.requests.get());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {503, 408, 421, 401, 407, 301, 302, 303, 307, 308})
    void neverRetriesRedirectsOrAnswersAuthenticationChallenges(int status) throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture
                    .respond(status, "Retry-After: 0\r\nLocation: https://core.test:" + fixture.listener.getLocalPort()
                            + "/followup\r\nWWW-Authenticate: Basic realm=fixture\r\nProxy-Authenticate: Basic realm=fixture\r\n",
                            WireBodies.ERROR);
            ProxyReply reply = new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap());
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, reply.outcome());
            assertEquals(status, reply.httpStatus());
            assertArrayEquals(WireBodies.ERROR, reply.payload());
            assertEquals(1, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
        }
    }

    @Test
    void resetAfterRequestIsUnknownAndNeverResent() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.reset = true;
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(1, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
        }
    }

    @Test
    void mismatchOrMissingIdentityIsNotSentBeforeAnyConnection() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var other = LocalTlsFixture.material("other", fixture.ca, false, null, false, "secp256r1");
            LocalTlsFixture
                    .writePem(directory.resolve("tls.key"), "PRIVATE KEY", other.keys().getPrivate().getEncoded());
            assertEquals(ProxyReply.Outcome.NOT_SENT,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.connections.get());
            Files.delete(directory.resolve("tls.key"));
            assertEquals(ProxyReply.Outcome.NOT_SENT,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.connections.get());
        }
    }

    @Test
    void rejectsATls12OnlyServerForTheTls13OnlyCoreListenerProfile() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.listener.setEnabledProtocols(new String[]{"TLSv1.2"});
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
        }
    }

    @Test
    void aHugeDeclaredBodyIsRejectedWithoutDrainingOrWaitingForIt() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.response = WireBodies
                    .bytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2147483647\r\n\r\n");
            fixture.stallAfterResponse = true;
            long started = System.nanoTime();
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertTrue(Duration.ofNanos(System.nanoTime() - started).toMillis() < 1500);
            fixture.peerFinished.get(1, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals(1, fixture.requests.get());
        }
    }

    @Test
    void aStalledTlsHandshakeIsCutOffAndItsSocketActuallyCloses() throws Exception {
        try (var fixture = new LocalTlsFixture(directory);
                var listener = new java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            var accepted = new java.util.concurrent.atomic.AtomicInteger();
            var firstTlsByte = new java.util.concurrent.atomic.AtomicInteger(-1);
            var peer = java.util.concurrent.CompletableFuture.runAsync(() -> {
                try (var socket = listener.accept()) {
                    accepted.incrementAndGet();
                    int value;
                    while ((value = socket.getInputStream().read()) != -1) {
                        firstTlsByte.compareAndSet(-1, value);
                    }
                } catch (java.net.SocketException closedByCutoff) {
                    // FIN or reset are both terminal closure of the actual accepted socket.
                } catch (java.io.IOException failure) {
                    throw new java.util.concurrent.CompletionException(failure);
                }
            });
            var original = fixture.configuration();
            var configuration = new ProxyConfiguration(URI.create("https://core.test:" + listener.getLocalPort()),
                    original.coreAddress(), original.certificateFile(), original.privateKeyFile(),
                    original.serverCaFile());
            long started = System.nanoTime();
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(configuration).execute(WireBodies.bootstrap()).outcome());
            assertTrue(Duration.ofNanos(System.nanoTime() - started).toMillis() < 6000);
            peer.get(1, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals(1, accepted.get());
            assertEquals(22, firstTlsByte.get());
        }
    }

    @Test
    void hostnameMismatchIsUnknownWithoutHttpRequest() throws Exception {
        try (var fixture = new LocalTlsFixture(directory, "wrong.test", false)) {
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
        }
    }

    @Test
    void rejectsUntrustedCaEvenWhenItIsAnotherLocallyValidCa() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var other = LocalTlsFixture.material("other-ca", null, true, null, false, "secp256r1");
            LocalTlsFixture.writePem(directory.resolve("ca.pem"), "CERTIFICATE", other.certificate().getEncoded());
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
        }
    }

    @Test
    void rejectsExpiredServerBeforeHttp() throws Exception {
        try (var fixture = new LocalTlsFixture(directory, "core.test", true)) {
            assertEquals(ProxyReply.Outcome.UNKNOWN,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.requests.get());
            assertEquals(1, fixture.connections.get());
        }
    }

    @Test
    void ignoresAmbientProxySelection() throws Exception {
        String previous = System.getProperty("https.proxyHost");
        System.setProperty("https.proxyHost", "192.0.2.1");
        try (var fixture = new LocalTlsFixture(directory)) {
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(1, fixture.requests.get());
        } finally {
            if (previous == null) {
                System.clearProperty("https.proxyHost");
            } else {
                System.setProperty("https.proxyHost", previous);
            }
        }
    }

    @Test
    void ignoresAnAmbientSocketProxySelector() throws Exception {
        var previous = java.net.ProxySelector.getDefault();
        java.net.ProxySelector.setDefault(new java.net.ProxySelector() {
            @Override
            public java.util.List<java.net.Proxy> select(URI uri) {
                return java.util.List
                        .of(new java.net.Proxy(java.net.Proxy.Type.SOCKS,
                                new java.net.InetSocketAddress("127.0.0.1", 1)));
            }

            @Override
            public void connectFailed(URI uri, java.net.SocketAddress address, java.io.IOException failure) {
            }
        });
        try (var fixture = new LocalTlsFixture(directory)) {
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(1, fixture.requests.get());
        } finally {
            java.net.ProxySelector.setDefault(previous);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "wrong-contract",
            "invalid-json",
            "empty",
            "oversize",
            "gzip",
            "headers",
            "header-line",
            "upgrade",
            "invalid-status",
            "old-http",
            "chunked-oversize",
            "no-content"})
    void returnsUnknownForUnboundedEncodedOrInvalidReplies(String kind) throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            switch (kind) {
                case "wrong-contract" -> fixture.respond(200, "", WireBodies.HEARTBEAT_REPLY);
                case "invalid-json" -> fixture.respond(200, "", WireBodies.bytes("{\"private\":\"CANARY\"}"));
                case "empty" -> fixture.respond(200, "", new byte[0]);
                case "oversize" -> fixture.respond(200, "", new byte[4097]);
                case "gzip" -> fixture.respond(200, "Content-Encoding: gzip\r\n", WireBodies.PENDING);
                case "headers" -> fixture.respond(200, "X-Test: value\r\n".repeat(80), WireBodies.PENDING);
                case "header-line" -> fixture.respond(200, "X-Test: " + "x".repeat(9000) + "\r\n", WireBodies.PENDING);
                case "invalid-status" -> fixture.respond(600, "", WireBodies.ERROR);
                case "old-http" ->
                    fixture.response = new String(fixture.response, java.nio.charset.StandardCharsets.ISO_8859_1)
                            .replace("HTTP/1.1", "HTTP/1.0")
                            .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                case "chunked-oversize" -> fixture.response = WireBodies
                        .bytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n"
                                + "x".repeat(4097) + "\r\n0\r\n\r\n");
                case "no-content" -> fixture.respond(204, "", new byte[0]);
                case "upgrade" -> fixture.response = WireBodies
                        .bytes("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: TLS/1.3\r\n\r\n");
                default -> throw new AssertionError(kind);
            }
            var reply = new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap());
            assertEquals(ProxyReply.Outcome.UNKNOWN, reply.outcome());
            assertEquals(0, reply.httpStatus());
            assertEquals(0, reply.payload().length);
            assertEquals(1, fixture.requests.get());
        }
    }

    @Test
    void anExpiredLocalBudgetIsNotSentBeforeOpeningAConnection() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var reply = new CoreRpcClient(fixture.configuration())
                    .execute(WireBodies.bootstrap(),
                            System.nanoTime() - java.util.concurrent.TimeUnit.SECONDS.toNanos(6));
            assertEquals(ProxyReply.Outcome.NOT_SENT, reply.outcome());
            assertEquals(0, fixture.connections.get());
        }
    }

    @Test
    void acceptsOnlyAControlledCoreErrorWhenSuccessContractIsAbsent() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.respond(200, "", WireBodies.ERROR);
            var reply = new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap());
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, reply.outcome());
            assertArrayEquals(WireBodies.ERROR, reply.payload());
        }
    }

    @Test
    void aDrippingResponseCannotResetTheTotalLocalDeadline() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.drip = true;
            long started = System.nanoTime();
            var reply = new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap());
            assertEquals(ProxyReply.Outcome.UNKNOWN, reply.outcome());
            assertEquals(1, fixture.requests.get());
            assertTrue(Duration.ofNanos(System.nanoTime() - started).toMillis() < 6000);
        }
    }

    @Test
    void cancelsAReadThatNeverFinishesWithinTheLocalFiveSecondBudget() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            fixture.stall = true;
            long start = System.nanoTime();
            var reply = new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap());
            long elapsedMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();
            assertEquals(ProxyReply.Outcome.UNKNOWN, reply.outcome());
            assertEquals(1, fixture.requests.get());
            assertTrue(elapsedMillis < 6000, "local cancellation did not bound blocking read");
        }
    }
}
