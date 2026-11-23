package com.otilm.ai.gateway;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Closed own-channel registration status only; a decoded READY does not authorize consumption. */
final class GatewayRegistrationWire {
    private GatewayRegistrationWire() {
    }

    static boolean ready(byte[] bytes, GatewayRun.Audience audience) {
        if (bytes == null || bytes.length == 0 || bytes.length > 4096 || audience == null) {
            throw GatewayRunWire.invalid();
        }
        try {
            var root = GatewayRunWire.JSON
                    .readTree(StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString());
            if (root == null || !root.isObject() || root.size() != 2 || !root.path("version").isIntegralNumber()
                    || !root.path("version").canConvertToInt() || root.path("version").intValue() != 1
                    || !root.path("kind").isTextual()) {
                throw GatewayRunWire.invalid();
            }
            String prefix = (audience == GatewayRun.Audience.MANAGEMENT ? "management" : "run")
                    + "-gateway-registration-";
            String kind = root.path("kind").textValue();
            if (kind.equals(prefix + "ready")) {
                return true;
            }
            if (kind.equals(prefix + "pending")) {
                return false;
            }
            throw GatewayRunWire.invalid();
        } catch (Exception invalid) {
            throw GatewayRunWire.invalid();
        }
    }
}
