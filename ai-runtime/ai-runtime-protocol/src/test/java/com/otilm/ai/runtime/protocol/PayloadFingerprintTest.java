package com.otilm.ai.runtime.protocol;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PayloadFingerprintTest {
    @Test
    void bindsExactBytesUsingKnownSha256Vectors() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                PayloadFingerprint.sha256(new byte[0]));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                PayloadFingerprint.sha256(bytes("abc")));
        assertEquals("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                PayloadFingerprint.sha256(bytes("a".repeat(1_000_000))));
        assertNotEquals(PayloadFingerprint.sha256(bytes("{}")), PayloadFingerprint.sha256(bytes("{ }")));
        assertNotEquals(PayloadFingerprint.sha256(bytes("abc")), PayloadFingerprint.sha256(bytes("abd")));
    }

    @Test
    void acceptsBoundaryRejectsOversizeAndNullAndDoesNotRetainBuffer() {
        byte[] input = new byte[1_048_576];
        String original = PayloadFingerprint.sha256(input);
        input[0] = 1;
        assertNotEquals(original, PayloadFingerprint.sha256(input));
        assertEquals(original, PayloadFingerprint.sha256(new byte[1_048_576]));
        ProtocolException oversize = assertThrows(ProtocolException.class,
                () -> PayloadFingerprint.sha256(new byte[1_048_577]));
        assertEquals(ProtocolException.Reason.INPUT_TOO_LARGE, oversize.reason());
        assertEquals(ProtocolException.Reason.INVALID_DISPATCH,
                assertThrows(ProtocolException.class, () -> PayloadFingerprint.sha256(null)).reason());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
