package com.czertainly.core.events.transaction;

import com.czertainly.api.exception.EventException;
import com.czertainly.api.model.core.other.ResourceEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TransactionHandlerTest {

    private TransactionHandler transactionHandler;

    @BeforeEach
    void setUp() {
        transactionHandler = new TransactionHandler();
    }

    @Test
    void runInTransaction_returnsValue() throws EventException {
        String result = transactionHandler.runInTransaction(() -> "ok");
        assertEquals("ok", result);
    }

    @Test
    void runInTransaction_rethrowsRuntimeException() {
        RuntimeException cause = new RuntimeException("boom");
        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> transactionHandler.runInTransaction(() -> { throw cause; }));
        assertSame(cause, thrown);
    }

    @Test
    void runInTransaction_rethrowsEventException() {
        EventException cause = new EventException(ResourceEvent.CERTIFICATE_DISCOVERED, "not found");
        EventException thrown = assertThrows(EventException.class,
                () -> transactionHandler.runInTransaction(() -> { throw cause; }));
        assertSame(cause, thrown);
    }

    @Test
    void runInTransaction_wrapsOtherCheckedExceptionInRuntimeException() {
        Exception cause = new Exception("checked");
        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> transactionHandler.runInTransaction(() -> { throw cause; }));
        assertSame(cause, thrown.getCause());
    }
}
