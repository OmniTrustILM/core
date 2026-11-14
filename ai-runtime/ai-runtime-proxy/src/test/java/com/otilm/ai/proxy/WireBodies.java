package com.otilm.ai.proxy;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

final class WireBodies {
    static final UUID CALL = UUID.fromString("11111111-1111-4111-8111-111111111111");
    static final byte[] BOOTSTRAP = bytes(
            "{\"protocolVersion\":1,\"runId\":\"22222222-2222-4222-8222-222222222222\",\"attemptId\":\"33333333-3333-4333-8333-333333333333\",\"podUid\":\"44444444-4444-4444-8444-444444444444\"}");
    static final byte[] PENDING = bytes("{\"status\":\"pending\",\"protocolVersion\":1,\"retryAfterMillis\":250}");
    static final byte[] HEARTBEAT = bytes(
            "{\"protocolVersion\":1,\"binding\":{\"runId\":\"22222222-2222-4222-8222-222222222222\",\"attemptId\":\"33333333-3333-4333-8333-333333333333\",\"podUid\":\"44444444-4444-4444-8444-444444444444\",\"claimId\":\"55555555-5555-4555-8555-555555555555\",\"fence\":7},\"sequence\":9}");
    static final byte[] HEARTBEAT_REPLY = bytes(
            "{\"protocolVersion\":1,\"binding\":{\"runId\":\"22222222-2222-4222-8222-222222222222\",\"attemptId\":\"33333333-3333-4333-8333-333333333333\",\"podUid\":\"44444444-4444-4444-8444-444444444444\",\"claimId\":\"55555555-5555-4555-8555-555555555555\",\"fence\":7},\"sequence\":9,\"leaseExpiresAt\":\"2026-10-26T12:00:00Z\"}");
    static final byte[] ERROR = bytes(
            "{\"protocolVersion\":1,\"code\":\"INVALID_REQUEST\",\"correlationId\":\"11111111-1111-4111-8111-111111111111\"}");

    static ProxyRequest bootstrap() {
        return new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, BOOTSTRAP);
    }

    static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
