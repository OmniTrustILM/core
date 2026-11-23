package com.otilm.core.service.ai;

import java.nio.charset.StandardCharsets;

/** Closed own-channel status; a READY label never grants consumption or actor authority. */
final class AiRuntimeRegistrationWire {
    private AiRuntimeRegistrationWire() {
    }

    static byte[] reply(boolean management, boolean ready) {
        String kind = (management ? "management" : "run") + "-gateway-registration-" + (ready ? "ready" : "pending");
        return ("{\"version\":1,\"kind\":\"" + kind + "\"}").getBytes(StandardCharsets.UTF_8);
    }
}
