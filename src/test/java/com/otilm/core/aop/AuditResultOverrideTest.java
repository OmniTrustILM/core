package com.otilm.core.aop;

import com.otilm.api.model.core.logging.enums.OperationResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit test for the request-scoped {@link AuditResultOverride} bean itself — its set/consume mechanics.
 * The controller behaviour that drives it (each TSP rejection path calls {@code setFailure()}, the
 * granted path does not) is verified in {@code TspControllerImplTest}.
 */
class AuditResultOverrideTest {

    @Test
    void consume_whenNothingSet_returnsNull() {
        // given
        var auditResultOverride = new AuditResultOverride();

        // when
        OperationResult result = auditResultOverride.consume();

        // then
        assertNull(result);
    }

    @Test
    void consume_afterSetFailure_returnsFailure() {
        // given
        var auditResultOverride = new AuditResultOverride();
        auditResultOverride.setFailure();

        // when
        OperationResult result = auditResultOverride.consume();

        // then
        assertEquals(OperationResult.FAILURE, result);
    }

    @Test
    void consume_isOnceOnly_secondReadReturnsNull() {
        // given
        var auditResultOverride = new AuditResultOverride();
        auditResultOverride.setFailure();

        // when
        OperationResult firstRead = auditResultOverride.consume();
        OperationResult secondRead = auditResultOverride.consume();

        // then
        assertEquals(OperationResult.FAILURE, firstRead);
        assertNull(secondRead);
    }
}
