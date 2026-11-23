package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.impl.io.DefaultHttpClientConnectionOperator;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.io.HttpClientConnectionOperator;
import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.pool.StrictConnPool;
import org.apache.hc.core5.util.TimeValue;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CleanupFailureTest {
    @org.junit.jupiter.api.io.TempDir
    java.nio.file.Path directory;
    private static final byte[] BODY = "{\"model\":\"fixture\",\"messages\":[{\"role\":\"user\",\"content\":\"synthetic\"}],\"max_tokens\":32,\"stream\":false}"
            .getBytes(StandardCharsets.UTF_8);
    private static final String DIGEST = PayloadFingerprint.sha256(BODY);

    @Test
    void failedProviderClosureCannotStartAnOutcomeOrReleaseTheConsumedOperation() throws Exception {
        var pool = new FaultPool(false);
        var transport = new ChatCompletionsTransport(Duration.ofSeconds(5), Duration.ofSeconds(1),
                Thread.ofPlatform().daemon().factory(), endpoint -> new FaultManager(operator(endpoint), pool));
        try (var fixture = new GatewayRunFixture(directory)) {
            fixture.providerStatus = 500;
            org.junit.jupiter.api.Assertions
                    .assertThrows(GatewayFailure.class, () -> GatewayRun
                            .execute(fixture.envelope, fixture.config, transport, GatewayRunWireTest.CALL));
            assertEquals(1, fixture.consumes.get());
            assertEquals(1, fixture.sends.get());
            assertTrue(pool.failureInjected.get());
            assertEquals(0, fixture.outcomes.get(), "No fresh Core I/O may follow a first uncertain provider close");
            org.junit.jupiter.api.Assertions
                    .assertThrows(GatewayFailure.class, () -> transport.admit(transport.accepted()));
        } finally {
            pool.forceClose();
        }
    }

    @Test
    void actualInstalledCoreClientCloseFailureQuarantinesTheWholeOperation() throws Exception {
        var pool = new FaultPool(false);
        var transport = new ChatCompletionsTransport();
        try (var server = new HttpsFixture(200, new byte[]{1, 2})) {
            var manager = new FaultManager(operator(server.endpoint()), pool);
            try (var client = org.apache.hc.client5.http.impl.classic.HttpClients
                    .custom()
                    .setConnectionManager(manager)
                    .disableAutomaticRetries()
                    .build()) {
                var operation = transport.admit(transport.accepted());
                var post = new org.apache.hc.client5.http.classic.methods.HttpPost(
                        server.endpoint().origin() + "/resource-control");
                operation.installCore(post, client);
                try (var response = client.executeOpen(null, post, null)) {
                    assertArrayEquals(new byte[]{1, 2}, response.getEntity().getContent().readAllBytes());
                }
                org.junit.jupiter.api.Assertions.assertThrows(GatewayFailure.class, operation::finishCore);
                org.junit.jupiter.api.Assertions.assertThrows(GatewayFailure.class, operation::close);
                org.junit.jupiter.api.Assertions
                        .assertThrows(GatewayFailure.class, () -> transport.admit(transport.accepted()));
                assertTrue(pool.failureInjected.get());
                assertTrue(manager.isClosed());
                assertEquals(1, server.requests.get());
            }
        } finally {
            pool.forceClose();
        }
    }

    @Test
    void realPostThenPartialManagerCloseFailureForbidsSecondActualPost() throws Exception {
        proveQuarantine(false);
    }

    @Test
    void realPostThenPartialManagerCloseErrorForbidsSecondActualPost() throws Exception {
        proveQuarantine(true);
    }

    private void proveQuarantine(boolean fatal) throws Exception {
        var calls = new AtomicInteger();
        var pool = new FaultPool(fatal);
        var manager = new AtomicReference<FaultManager>();
        var selected = new ChatCompletionsTransport(Duration.ofSeconds(5), Duration.ofSeconds(1),
                Thread.ofPlatform().factory(), endpoint -> {
                    if (calls.incrementAndGet() == 1) {
                        var created = new FaultManager(operator(endpoint), pool);
                        manager.set(created);
                        return created;
                    }
                    return ChatCompletionsTransport.newManager(endpoint);
                });
        try (var failed = new HttpsFixture(500, new byte[]{1}); var next = new HttpsFixture(200, new byte[]{1, 2})) {
            Throwable first = null;
            try {
                selected.post(failed.endpoint(), BODY, DIGEST, "synthetic-token");
            } catch (GatewayFailure | CloseFailureError failure) {
                first = failure;
            }
            assertNotNull(first);
            if (fatal) {
                assertSame(pool.error, first, "The original Error must propagate");
            } else {
                assertEquals(GatewayFailure.Code.UPSTREAM_FAILURE, ((GatewayFailure) first).code());
            }
            assertArrayEquals(BODY, failed.received.get());
            assertEquals(1, failed.requests.get());
            assertTrue(pool.failureInjected.get());
            // This is the actual Apache manager's closed CAS, not a simulated transport flag.
            assertTrue(manager.get().isClosed());
            GatewayFailure second = null;
            try {
                selected.post(next.endpoint(), BODY, DIGEST, "synthetic-token");
            } catch (GatewayFailure failure) {
                second = failure;
            }
            GatewayFailure observed = second;
            System.out
                    .println("GATEWAY_CLOSE_FAILURE firstActualPOST=" + failed.requests.get() + " nativeClosedCAS="
                            + manager.get().isClosed() + " closeFailureInjected=" + pool.failureInjected.get()
                            + " secondActualPOST=" + next.requests.get());
            assertAll(() -> assertNotNull(observed, "Cleanup uncertainty must quarantine admission"),
                    () -> assertEquals(0, next.requests.get(), "Second real POST escaped after partial close"),
                    () -> assertEquals(1, calls.get(), "No second resource allocation is allowed"));
        } finally {
            // Exact owned real pool cleanup even for RED; bypass only our fault to finish actual socket disposal.
            pool.forceClose();
        }
    }

    private static HttpClientConnectionOperator operator(PinnedEndpoint endpoint) {
        var dns = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                if (!host.equals(endpoint.origin().getHost())) {
                    throw new UnknownHostException("UNAPPROVED_HOST");
                }
                return endpoint.addresses().toArray(InetAddress[]::new);
            }

            @Override
            public String resolveCanonicalHostname(String host) throws UnknownHostException {
                resolve(host);
                return endpoint.origin().getHost();
            }
        };
        var tls = ClientTlsStrategyBuilder
                .create()
                .setSslContext(endpoint.trust())
                .setHostnameVerifier(new DefaultHostnameVerifier())
                .setTlsVersions(TLS.V_1_3, TLS.V_1_2)
                .buildClassic();
        return new DefaultHttpClientConnectionOperator(null, dns,
                RegistryBuilder.<TlsSocketStrategy>create().register("https", tls).build());
    }

    private static final class FaultManager extends PoolingHttpClientConnectionManager {
        FaultManager(HttpClientConnectionOperator operator, FaultPool pool) {
            super(operator, pool, ManagedHttpClientConnectionFactory.INSTANCE);
        }
    }

    private static final class CloseFailureError extends Error {
        private static final long serialVersionUID = 1L;
    }

    private static final class FaultPool extends StrictConnPool<HttpRoute, ManagedHttpClientConnection> {
        final AtomicBoolean failureInjected = new AtomicBoolean();
        final CloseFailureError error = new CloseFailureError();
        private final boolean fatal;

        FaultPool(boolean fatal) {
            super(1, 1, TimeValue.NEG_ONE_MILLISECOND, PoolReusePolicy.LIFO, null);
            this.fatal = fatal;
        }

        @Override
        public void close(CloseMode mode) {
            if (failureInjected.compareAndSet(false, true)) {
                if (fatal) {
                    throw error;
                }
                throw new IllegalStateException("CONTROLLED_PARTIAL_CLOSE_CANARY");
            }
            super.close(mode);
        }

        void forceClose() {
            super.close(CloseMode.IMMEDIATE);
        }
    }
}
