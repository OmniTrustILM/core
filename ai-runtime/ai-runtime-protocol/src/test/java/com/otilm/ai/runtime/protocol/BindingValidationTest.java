package com.otilm.ai.runtime.protocol;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BindingValidationTest {
    private static final UUID ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final Instant EXPIRY = Instant.parse("2026-10-26T12:00:00Z");
    private static final String DIGEST = "a".repeat(64);

    @Test
    void programmaticBindingsRejectMissingValuesAndNonPositiveCounters() {
        assertInvalid(() -> new RunBinding(null, ID, ID, ID, 1, EXPIRY));
        assertInvalid(() -> new RunBinding(ID, null, ID, ID, 1, EXPIRY));
        assertInvalid(() -> new RunBinding(ID, ID, null, ID, 1, EXPIRY));
        assertInvalid(() -> new RunBinding(ID, ID, ID, null, 1, EXPIRY));
        assertInvalid(() -> new RunBinding(ID, ID, ID, ID, 1, null));
        assertInvalid(() -> new RunBinding(ID, ID, ID, ID, 0, EXPIRY));
        assertInvalid(() -> new RunBinding(ID, ID, ID, ID, -1, EXPIRY));
        assertInvalid(() -> new ManagementBinding(null, ID, ID, 1, ManagementAction.CONNECTION_CHECK, EXPIRY));
        assertInvalid(() -> new ManagementBinding(ID, null, ID, 1, ManagementAction.CONNECTION_CHECK, EXPIRY));
        assertInvalid(() -> new ManagementBinding(ID, ID, null, 1, ManagementAction.CONNECTION_CHECK, EXPIRY));
        assertInvalid(() -> new ManagementBinding(ID, ID, ID, 1, null, EXPIRY));
        assertInvalid(() -> new ManagementBinding(ID, ID, ID, 1, ManagementAction.CONNECTION_CHECK, null));
        assertInvalid(() -> new ManagementBinding(ID, ID, ID, 0, ManagementAction.CONNECTION_CHECK, EXPIRY));
        assertInvalid(() -> new ManagementBinding(ID, ID, ID, -1, ManagementAction.CONNECTION_CHECK, EXPIRY));
    }

    @Test
    void programmaticEnvelopesCannotSerializeInvalidAuthorityReferences() {
        RunBinding run = new RunBinding(ID, ID, ID, ID, Long.MAX_VALUE, EXPIRY);
        ManagementBinding management = new ManagementBinding(ID, ID, ID, Long.MAX_VALUE,
                ManagementAction.CAPABILITY_CHECK, EXPIRY);
        assertInvalid(() -> new RunDispatchEnvelope(1, null, DIGEST, run));
        assertInvalid(() -> new RunDispatchEnvelope(1, ID, null, run));
        assertInvalid(() -> new RunDispatchEnvelope(1, ID, "private-canary-credential", run));
        assertInvalid(() -> new RunDispatchEnvelope(1, ID, DIGEST, null));
        assertInvalid(() -> new ManagementDispatchEnvelope(1, ID, DIGEST, null));
        assertEquals(ProtocolException.Reason.UNSUPPORTED_VERSION,
                assertThrows(ProtocolException.class, () -> new ManagementDispatchEnvelope(2, ID, DIGEST, management))
                        .reason());
        assertEquals(Long.MAX_VALUE,
                ((RunDispatchEnvelope) new ProtocolCodec()
                        .readDispatch(new ProtocolCodec().writeDispatch(new RunDispatchEnvelope(1, ID, DIGEST, run))))
                        .binding()
                        .fence());
    }

    private static void assertInvalid(org.junit.jupiter.api.function.Executable executable) {
        assertEquals(ProtocolException.Reason.INVALID_DISPATCH,
                assertThrows(ProtocolException.class, executable).reason());
    }
}
