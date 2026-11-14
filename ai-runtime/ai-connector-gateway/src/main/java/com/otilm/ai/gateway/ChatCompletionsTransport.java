package com.otilm.ai.gateway;

import com.otilm.ai.proxy.FixedCoreHttp;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;

// Internal transport component. No public ingress, allow callback or Core redemption approximation.
final class ChatCompletionsTransport {
    private static final int MAX_BYTES = 1048576;
    private final long operationNanos;
    private final long cleanupNanos;
    private final ThreadFactory watchdogs;
    private final Function<PinnedEndpoint, PoolingHttpClientConnectionManager> managerFactory;
    private final AtomicReference<Operation> admitted = new AtomicReference<>();

    ChatCompletionsTransport() {
        this(Duration.ofSeconds(5), Duration.ofSeconds(1),
                Thread.ofPlatform().name("ilm-ai-gateway-watchdog-", 0).daemon(true).factory());
    }

    // Trusted component policy/lifecycle seam, never selected by request data.
    ChatCompletionsTransport(Duration operationLimit, Duration cleanupLimit, ThreadFactory watchdogs) {
        this(operationLimit, cleanupLimit, watchdogs, ChatCompletionsTransport::newManager);
    }

    // Trusted resource factory for lifecycle fault controls, never request-selected and no authorization callback.
    ChatCompletionsTransport(Duration operationLimit, Duration cleanupLimit, ThreadFactory watchdogs,
            Function<PinnedEndpoint, PoolingHttpClientConnectionManager> managerFactory) {
        operationNanos = Objects.requireNonNull(operationLimit).toNanos();
        cleanupNanos = Objects.requireNonNull(cleanupLimit).toNanos();
        if (operationNanos <= 0 || operationNanos > TimeUnit.SECONDS.toNanos(5) || cleanupNanos <= 0
                || cleanupNanos > TimeUnit.SECONDS.toNanos(1)) {
            throw new IllegalArgumentException("INVALID_TRANSPORT_POLICY");
        }
        this.watchdogs = Objects.requireNonNull(watchdogs);
        this.managerFactory = Objects.requireNonNull(managerFactory);
    }

    // Create at authenticated acceptance; carry this same trusted object through parsing/online consume.
    Deadline accepted() {
        return new Deadline(System.nanoTime());
    }

    Deadline accepted(long started) {
        return new Deadline(started);
    }

    Operation admit(Deadline deadline) {
        if (deadline == null || deadline.transport != this || !deadline.claimed.compareAndSet(false, true)) {
            throw uncertain();
        }
        if (deadline.remaining() <= 0 || Thread.currentThread().isInterrupted()) {
            throw uncertain();
        }
        var operation = new Operation(deadline);
        if (!admitted.compareAndSet(null, operation)) {
            throw uncertain();
        }
        try {
            operation.start();
            return operation;
        } catch (RuntimeException failure) {
            if (operation.watchdog == null || !operation.watchdog.isAlive()) {
                admitted.compareAndSet(operation, null);
            }
            throw uncertain();
        }
    }

    final class Deadline {
        private final ChatCompletionsTransport transport = ChatCompletionsTransport.this;
        private final long started;
        private final AtomicBoolean claimed = new AtomicBoolean();

        private Deadline(long started) {
            this.started = started;
        }

        private long remaining() {
            return operationNanos - (System.nanoTime() - started);
        }
    }

    final class Operation implements AutoCloseable {
        private final Deadline deadline;
        private final Thread owner = Thread.currentThread();
        private final CountDownLatch stop = new CountDownLatch(1);
        private volatile HttpUriRequestBase request;
        private volatile PoolingHttpClientConnectionManager manager;
        private volatile CloseableHttpClient coreClient;
        private volatile boolean cleanupFailed;
        private volatile boolean expired;
        private boolean ioFinished = true;
        private boolean used;
        private boolean closed;
        private Thread watchdog;

        private Operation(Deadline deadline) {
            this.deadline = deadline;
        }

        private void start() {
            watchdog = Objects.requireNonNull(watchdogs.newThread(() -> {
                try {
                    long remaining = deadline.remaining();
                    if (remaining <= 0 || !stop.await(remaining, TimeUnit.NANOSECONDS)) {
                        expired = true;
                        abortIO();
                    }
                } catch (InterruptedException interrupted) {
                    expired = true;
                    abortIO();
                    Thread.currentThread().interrupt();
                }
            }));
            if (watchdog.getState() != Thread.State.NEW) {
                throw uncertain();
            }
            watchdog.start();
        }

        byte[] post(PinnedEndpoint endpoint, byte[] exactPayload, String expectedDigest, String bearer) {
            byte[] result;
            try (var operation = this) {
                result = postWithin(endpoint, exactPayload, expectedDigest, bearer);
            }
            ensureBudget();
            return result;
        }

        byte[] postWithin(PinnedEndpoint endpoint, byte[] exactPayload, String expectedDigest, String bearer) {
            requireOwner();
            if (used || closed) {
                throw uncertain();
            }
            used = true;
            ensureBudget();
            byte[] result = validatedPost(this, endpoint, exactPayload, expectedDigest, bearer);
            ensureBudget();
            return result;
        }

        long remaining() {
            requireOwner();
            ensureBudget();
            return deadline.remaining();
        }

        void installCore(HttpUriRequestBase selected, CloseableHttpClient client) {
            requireOwner();
            ensureBudget();
            if (!ioFinished || coreClient != null || manager != null || closed) {
                throw uncertain();
            }
            request = selected;
            coreClient = client;
            ioFinished = false;
        }

        void finishCore() {
            requireOwner();
            ioFinished = abortIO();
            if (ioFinished) {
                request = null;
                coreClient = null;
            }
            if (!ioFinished || cleanupFailed) {
                throw uncertain();
            }
        }

        void cleanupUncertain() {
            cleanupFailed = true;
        }

        private void ensureBudget() {
            if (cleanupFailed || expired || deadline.remaining() <= 0 || Thread.currentThread().isInterrupted()) {
                throw uncertain();
            }
        }

        private void install(HttpPost selected, PoolingHttpClientConnectionManager connections) {
            if (!ioFinished || coreClient != null || closed) {
                throw uncertain();
            }
            request = selected;
            manager = connections;
            ioFinished = false;
            ensureBudget();
        }

        private boolean abortIO() {
            boolean completed = false;
            try {
                HttpUriRequestBase selected = request;
                if (selected != null) {
                    selected.cancel();
                }
                CloseableHttpClient core = coreClient;
                if (core != null) {
                    core.close(CloseMode.IMMEDIATE);
                }
                PoolingHttpClientConnectionManager connections = manager;
                if (connections != null) {
                    connections.close(CloseMode.IMMEDIATE);
                }
                completed = true;
                return true;
            } catch (RuntimeException failure) {
                return false;
            } finally {
                // Any incomplete abort stays uncertain, including an Error that must propagate unchanged.
                if (!completed) {
                    cleanupFailed = true;
                }
            }
        }

        private void requireOwner() {
            if (Thread.currentThread() != owner) {
                throw uncertain();
            }
        }

        @Override
        public void close() {
            requireOwner();
            if (closed) {
                return;
            }
            closed = true;
            stop.countDown();
            boolean interrupted = Thread.interrupted();
            long started = System.nanoTime();
            try {
                while (watchdog.isAlive()) {
                    long remaining = cleanupNanos - (System.nanoTime() - started);
                    if (remaining <= 0) {
                        break;
                    }
                    try {
                        TimeUnit.NANOSECONDS.timedJoin(watchdog, remaining);
                    } catch (InterruptedException signal) {
                        interrupted = true;
                    }
                }
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            // Only the original blocking call's completed resource-finally and actual thread exit release admission.
            // If either is unacknowledged, this exact operation remains quarantined; no timer or flag releases it.
            // Detect actual watchdog termination before reading its final sticky cleanup result.
            if (!ioFinished || watchdog.isAlive() || cleanupFailed) {
                throw uncertain();
            }
            admitted.compareAndSet(this, null);
        }
    }

    private static GatewayFailure uncertain() {
        return new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
    }

    byte[] post(PinnedEndpoint endpoint, byte[] exactPayload, String expectedDigest, String bearer) {
        try (var operation = admit(accepted())) {
            return operation.post(endpoint, exactPayload, expectedDigest, bearer);
        }
    }

    private byte[] validatedPost(Operation operation, PinnedEndpoint endpoint, byte[] exactPayload,
            String expectedDigest, String bearer) {
        if (endpoint == null || exactPayload == null || exactPayload.length == 0 || exactPayload.length > MAX_BYTES
                || expectedDigest == null || !expectedDigest.matches("[0-9a-f]{64}") || bearer == null
                || bearer.length() > 4096 || !bearer.matches("[A-Za-z0-9._~+/=-]+")) {
            throw new GatewayFailure(GatewayFailure.Code.INVALID_REQUEST);
        }
        byte[] payload = exactPayload.clone();
        try {
            if (!PayloadFingerprint.sha256(payload).equals(expectedDigest)) {
                throw new GatewayFailure(GatewayFailure.Code.INVALID_REQUEST);
            }
            return exchange(operation, endpoint, payload, bearer);
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    private byte[] exchange(Operation operation, PinnedEndpoint endpoint, byte[] payload, String bearer) {
        var request = new HttpPost(endpoint.origin().resolve("/v1/chat/completions"));
        request
                .setEntity(new org.apache.hc.core5.http.io.entity.InputStreamEntity(
                        new java.io.ByteArrayInputStream(payload), payload.length, ContentType.APPLICATION_JSON));
        request.setHeader("Authorization", "Bearer " + bearer);
        request.setHeader("Accept", "application/json");
        request.setHeader("Accept-Encoding", "identity");
        request
                .setConfig(RequestConfig
                        .custom()
                        .setConnectionRequestTimeout(Timeout.ofMilliseconds(250))
                        .setResponseTimeout(Timeout.ofSeconds(1))
                        .setHardCancellationEnabled(true)
                        .setAuthenticationEnabled(false)
                        .setProtocolUpgradeEnabled(false)
                        .setExpectContinueEnabled(false)
                        .build());
        var manager = Objects.requireNonNull(managerFactory.apply(endpoint));
        CloseableHttpClient client = null;
        try {
            operation.install(request, manager);
            client = HttpClients
                    .custom()
                    .setConnectionManager(manager)
                    .setRequestExecutor(FixedCoreHttp.singleAttemptExecutor())
                    .setConnectionManagerShared(true)
                    .disableRedirectHandling()
                    .disableContentCompression()
                    .disableAutomaticRetries()
                    .disableCookieManagement()
                    .disableAuthCaching()
                    .setUserAgent("ilm-ai-gateway/1")
                    .build();
            operation.ensureBudget();
            return receive(operation, endpoint, request, client);
        } catch (GatewayFailure failure) {
            throw failure;
        } catch (IOException | RuntimeException failure) {
            // This code never certifies that no request was sent; an integrated consumed intent may be UNKNOWN.
            throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
        } finally {
            boolean closed = operation.abortIO();
            if (client != null) {
                try {
                    client.close(CloseMode.IMMEDIATE);
                } catch (RuntimeException failure) {
                    closed = false;
                    operation.cleanupFailed = true;
                }
            }
            operation.ioFinished = closed;
            if (closed) {
                operation.request = null;
                operation.manager = null;
            }
        }
    }

    static PoolingHttpClientConnectionManager newManager(PinnedEndpoint endpoint) {
        return PoolingHttpClientConnectionManagerBuilder
                .create()
                .setDnsResolver(resolver(endpoint))
                .setTlsSocketStrategy(ClientTlsStrategyBuilder
                        .create()
                        .setSslContext(endpoint.trust())
                        .setHostnameVerifier(new DefaultHostnameVerifier())
                        .setTlsVersions(TLS.V_1_3, TLS.V_1_2)
                        .buildClassic())
                .setMaxConnTotal(1)
                .setMaxConnPerRoute(1)
                .setDefaultConnectionConfig(ConnectionConfig
                        .custom()
                        .setConnectTimeout(Timeout.ofSeconds(1))
                        .setSocketTimeout(Timeout.ofSeconds(1))
                        .build())
                .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(Timeout.ofSeconds(1)).build())
                .setConnectionFactory(ManagedHttpClientConnectionFactory
                        .builder()
                        .http1Config(Http1Config
                                .custom()
                                .setMaxHeaderCount(32)
                                .setMaxLineLength(8192)
                                .setMaxEmptyLineCount(1)
                                .build())
                        .build())
                .build();
    }

    private byte[] receive(Operation operation, PinnedEndpoint endpoint, HttpPost request, CloseableHttpClient client)
            throws IOException {
        try (var response = client.executeOpen(HttpHost.create(endpoint.origin()), request, null)) {
            return readResponse(operation, response);
        }
    }

    private byte[] readResponse(Operation operation, ClassicHttpResponse response) throws IOException {
        try {
            operation.ensureBudget();
            if (response.getCode() != 200) {
                throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
            }
            if (response.containsHeader("Content-Encoding")) {
                throw new GatewayFailure(GatewayFailure.Code.UNSUPPORTED_ENCODING);
            }
            var entity = response.getEntity();
            if (entity == null) {
                throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
            }
            if (entity.getContentLength() > MAX_BYTES) {
                throw new GatewayFailure(GatewayFailure.Code.RESPONSE_LIMIT);
            }
            ContentType type = ContentType.parse(entity.getContentType());
            if (type == null || !type.getMimeType().equals("application/json")
                    || (type.getCharset() != null && !type.getCharset().equals(StandardCharsets.UTF_8))) {
                throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
            }
            var output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            var input = entity.getContent();
            while (true) {
                operation.ensureBudget();
                int count = input.read(buffer, 0, Math.min(buffer.length, MAX_BYTES + 1 - output.size()));
                operation.ensureBudget();
                if (count < 0) {
                    return output.toByteArray();
                }
                output.write(buffer, 0, count);
                if (output.size() > MAX_BYTES) {
                    throw new GatewayFailure(GatewayFailure.Code.RESPONSE_LIMIT);
                }
            }
        } catch (RuntimeException | IOException failure) {
            // Abort before the enclosing response resource closes; never drain an invalid/over-limit response.
            // Keep any first cancellation/manager-close failure sticky before response.close/finally can retry.
            operation.abortIO();
            throw failure;
        }
    }

    private static DnsResolver resolver(PinnedEndpoint endpoint) {
        return new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                if (!endpoint.origin().getHost().equalsIgnoreCase(host)) {
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
    }
}
