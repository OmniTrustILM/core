package com.otilm.ai.proxy;

import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.ProtocolException;
import java.io.ByteArrayInputStream;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;

/** One fixed Core control operation. A new TLS context and non-pooled connection belong to each call. */
public final class CoreRpcClient {
    static final long BUDGET_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final ProtocolCodec CODEC = new ProtocolCodec();
    private final ProxyConfiguration configuration;

    public CoreRpcClient(ProxyConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration);
    }

    public ProxyReply execute(ProxyRequest request) {
        return execute(request, System.nanoTime());
    }

    ProxyReply execute(ProxyRequest request, long started) {
        SSLContext sslContext;
        try {
            sslContext = IdentityFiles.load(configuration);
            if (remaining(started) <= 0) {
                return result(request, ProxyReply.Outcome.NOT_SENT);
            }
        } catch (Exception unavailable) {
            return result(request, ProxyReply.Outcome.NOT_SENT);
        }
        HttpPost post = new HttpPost(
                java.net.URI.create(configuration.coreOrigin().toASCIIString() + request.operation().path()));
        post.setVersion(HttpVersion.HTTP_1_1);
        post.setHeader(HttpHeaders.CONNECTION, "close");
        post.setHeader(HttpHeaders.ACCEPT, "application/json");
        byte[] body = request.payload();
        post
                .setEntity(new InputStreamEntity(new ByteArrayInputStream(body), body.length,
                        ContentType.APPLICATION_JSON));
        var watchdog = Executors
                .newSingleThreadScheduledExecutor(Thread.ofPlatform().daemon().name("core-rpc-cutoff").factory());
        try (CloseableHttpClient client = client(sslContext, started)) {
            long budget = remaining(started);
            if (budget <= 0) {
                return result(request, ProxyReply.Outcome.NOT_SENT);
            }
            var cutoff = watchdog.schedule(() -> {
                post.cancel();
                client.close(CloseMode.IMMEDIATE);
            }, budget, TimeUnit.NANOSECONDS);
            try {
                CloseableHttpResponse response = CloseableHttpResponse.adapt(client.executeOpen(null, post, null));
                try {
                    int status = response.getCode();
                    if (status < 200 || status > 599 || !HttpVersion.HTTP_1_1.equals(response.getVersion())
                            || response.containsHeader(HttpHeaders.CONTENT_ENCODING) || response.getEntity() == null
                            || response.getEntity().getContentLength() > FrameCodec.MAX_PAYLOAD_BYTES) {
                        return result(request, ProxyReply.Outcome.UNKNOWN);
                    }
                    byte[] payload = response.getEntity().getContent().readNBytes(FrameCodec.MAX_PAYLOAD_BYTES + 1);
                    if (payload.length == 0 || payload.length > FrameCodec.MAX_PAYLOAD_BYTES
                            || remaining(started) <= 0) {
                        return result(request, ProxyReply.Outcome.UNKNOWN);
                    }
                    validate(request.operation(), status, payload);
                    return new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, request.correlationId(), status, payload);
                } finally {
                    // Immediate close avoids an unbounded entity drain after a rejected reply.
                    response.close(CloseMode.IMMEDIATE);
                }
            } finally {
                cutoff.cancel(false);
            }
        } catch (Exception ambiguous) {
            return result(request, ProxyReply.Outcome.UNKNOWN);
        } finally {
            watchdog.shutdownNow();
            java.util.Arrays.fill(body, (byte) 0);
        }
    }

    private CloseableHttpClient client(SSLContext sslContext, long started) {
        return FixedCoreHttp
                .open(new CoreEndpoint(configuration.coreOrigin(), configuration.coreAddress()), sslContext,
                        remaining(started));
    }

    private static void validate(LocalOperation operation, int status, byte[] payload) {
        if (status < 300) {
            try {
                switch (operation) {
                    case BOOTSTRAP -> CODEC.readBootstrapReply(payload);
                    case HEARTBEAT -> CODEC.readClaimHeartbeatReply(payload);
                }
                return;
            } catch (ProtocolException invalidSuccess) {
                // Core may return its closed error contract for either operation.
            }
        }
        CODEC.readRuntimeError(payload);
    }

    private static ProxyReply result(ProxyRequest request, ProxyReply.Outcome outcome) {
        return new ProxyReply(outcome, request.correlationId(), 0, new byte[0]);
    }

    static Timeout transportTimeout(long remainingNanos) {
        return FixedCoreHttp.timeout(remainingNanos);
    }

    private static long remaining(long started) {
        return BUDGET_NANOS - (System.nanoTime() - started);
    }

}
