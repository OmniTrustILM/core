package com.otilm.ai.gateway;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayRegistrationWireTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void onlyTheExactOwnRoleVersionOneReadyOrPendingKindIsAccepted(boolean management) {
        var audience = management ? GatewayRun.Audience.MANAGEMENT : GatewayRun.Audience.RUN;
        String prefix = management ? "management" : "run";
        assertTrue(GatewayRegistrationWire.ready(body(prefix + "-gateway-registration-ready"), audience));
        assertFalse(GatewayRegistrationWire.ready(body(prefix + "-gateway-registration-pending"), audience));
        assertThrows(GatewayFailure.class, () -> GatewayRegistrationWire
                .ready(body((management ? "run" : "management") + "-gateway-registration-ready"), audience));
        assertThrows(GatewayFailure.class, () -> GatewayRegistrationWire.ready(body(prefix + "-consumed"), audience));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{}",
            "[]",
            "null",
            "{\"version\":2,\"kind\":\"run-gateway-registration-ready\"}",
            "{\"version\":1.0,\"kind\":\"run-gateway-registration-ready\"}",
            "{\"version\":1,\"version\":1,\"kind\":\"run-gateway-registration-ready\"}",
            "{\"version\":1,\"kind\":\"run-gateway-registration-ready\",\"runId\":\"selector\"}",
            "{\"version\":1,\"kind\":\"run-gateway-registration-ready\"} {}"})
    void malformedOrExtendedStatusCannotBecomeReady(String value) {
        assertThrows(GatewayFailure.class,
                () -> GatewayRegistrationWire.ready(value.getBytes(StandardCharsets.UTF_8), GatewayRun.Audience.RUN));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unsupportedBodyEncodingAndBoundsCannotBecomeAStatus(boolean utf16) {
        byte[] bytes = utf16
                ? new String(body("run-gateway-registration-ready"), StandardCharsets.UTF_8)
                        .getBytes(StandardCharsets.UTF_16)
                : new byte[4097];
        assertThrows(GatewayFailure.class, () -> GatewayRegistrationWire.ready(bytes, GatewayRun.Audience.RUN));
    }

    private static byte[] body(String kind) {
        return ("{\"version\":1,\"kind\":\"" + kind + "\"}").getBytes(StandardCharsets.UTF_8);
    }
}
