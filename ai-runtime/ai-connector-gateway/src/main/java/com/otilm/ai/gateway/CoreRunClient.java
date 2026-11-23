package com.otilm.ai.gateway;

import com.otilm.ai.proxy.FixedCoreHttp;
import com.otilm.ai.runtime.protocol.DispatchEnvelope;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Objects;
import java.util.UUID;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.io.CloseMode;

/** Exactly one consume and one outcome route; only the actual Core service can confer authority. */
final class CoreRunClient {
    private final GatewayRunConfiguration configuration;
    private final GatewayRun.Audience audience;
    private boolean consumeAttempted;
    private boolean consumed;
    private boolean reported;
    private DispatchEnvelope consumedEnvelope;
    private UUID consumedCorrelation;

    CoreRunClient(GatewayRunConfiguration configuration) {
        this(configuration, GatewayRun.Audience.RUN);
    }

    CoreRunClient(GatewayRunConfiguration configuration, GatewayRun.Audience audience) {
        this.configuration = Objects.requireNonNull(configuration);
        this.audience = Objects.requireNonNull(audience);
    }

    GatewayRunWire.Consumed consume(DispatchEnvelope envelope, UUID correlation,
            ChatCompletionsTransport.Operation operation) {
        if (consumeAttempted || !audience.accepts(envelope)) {
            throw GatewayRunWire.invalid();
        }
        consumeAttempted = true;
        awaitRegistration(operation);
        var reply = GatewayRunWire
                .consumed(call(audience.redeemPath(), GatewayRunWire.redeem(envelope, correlation),
                        GatewayRunWire.DOCUMENT_LIMIT, operation), envelope, correlation);
        consumedEnvelope = envelope;
        consumedCorrelation = correlation;
        consumed = true;
        return reply;
    }

    long report(DispatchEnvelope envelope, UUID correlation, byte[] outcome,
            ChatCompletionsTransport.Operation operation) {
        if (!consumed || reported || !consumedEnvelope.equals(envelope) || !consumedCorrelation.equals(correlation)) {
            throw GatewayRunWire.invalid();
        }
        reported = true;
        return GatewayRunWire
                .acknowledgement(call(audience.outcomePath(), outcome, 4096, operation), envelope, correlation,
                        outcome);
    }

    private void awaitRegistration(ChatCompletionsTransport.Operation operation) {
        for (int poll = 0; poll < 32; poll++) {
            operation.remaining();
            byte[] reply = call(audience.registrationPath(), null, 4096, operation);
            if (GatewayRegistrationWire.ready(reply, audience)) {
                operation.remaining();
                return;
            }
            if (poll == 31) {
                throw GatewayRunWire.invalid();
            }
            try {
                java.util.concurrent.TimeUnit.NANOSECONDS.sleep(Math.min(100_000_000L, operation.remaining()));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw GatewayRunWire.invalid();
            }
            operation.remaining();
        }
        throw GatewayRunWire.invalid();
    }

    private byte[] call(String route, byte[] body, int maximum, ChatCompletionsTransport.Operation operation) {
        operation.remaining();
        var identity = configuration.identity();
        var client = FixedCoreHttp.open(configuration.core(), identity, operation.remaining());
        var destination = java.net.URI.create(configuration.core().origin().toASCIIString() + route);
        HttpUriRequestBase request = request(destination, body);
        boolean installed = false;
        try {
            operation.installCore(request, client);
            installed = true;
            operation.remaining();
            var response = CloseableHttpResponse.adapt(client.executeOpen(null, request, null));
            try {
                return readReply(response, maximum, operation);
            } finally {
                response.close(CloseMode.IMMEDIATE);
            }
        } catch (Exception failed) {
            throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
        } finally {
            if (installed) {
                operation.finishCore();
            } else {
                try {
                    client.close(CloseMode.IMMEDIATE);
                } catch (RuntimeException cleanup) {
                    operation.cleanupUncertain();
                }
            }
        }
    }

    private static HttpUriRequestBase request(java.net.URI destination, byte[] body) {
        HttpUriRequestBase request;
        if (body == null) {
            request = new HttpGet(destination);
        } else {
            var post = new HttpPost(destination);
            post
                    .setEntity(new InputStreamEntity(new ByteArrayInputStream(body), body.length,
                            ContentType.APPLICATION_JSON));
            request = post;
        }
        request.setVersion(HttpVersion.HTTP_1_1);
        request.setHeader("Connection", "close");
        request.setHeader("Accept", "application/json");
        request.setHeader("Cache-Control", "no-store");
        return request;
    }

    private static byte[] readReply(CloseableHttpResponse response, int maximum,
            ChatCompletionsTransport.Operation operation) throws java.io.IOException {
        if (response.getCode() != 200 || !HttpVersion.HTTP_1_1.equals(response.getVersion())
                || response.containsHeader("Content-Encoding") || response.containsHeader("Set-Cookie")
                || response.containsHeader("Set-Cookie2") || response.getHeaders("Content-Type").length != 1
                || response.getEntity() == null || response.getEntity().getContentLength() > maximum) {
            throw GatewayRunWire.invalid();
        }
        String type = response.getFirstHeader("Content-Type").getValue();
        if (type == null || type.length() > 128 || !type
                .matches(
                        "(?i)[ \\t]*+application/json[ \\t]*+(?:;[ \\t]*+charset[ \\t]*+=[ \\t]*+(?:utf-8|\"utf-8\"))?[ \\t]*+")) {
            throw GatewayRunWire.invalid();
        }
        var output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        var input = response.getEntity().getContent();
        while (true) {
            operation.remaining();
            int count = input.read(buffer, 0, Math.min(buffer.length, maximum + 1 - output.size()));
            operation.remaining();
            if (count < 0) {
                return output.toByteArray();
            }
            output.write(buffer, 0, count);
            if (output.size() > maximum) {
                throw GatewayRunWire.invalid();
            }
        }
    }
}
