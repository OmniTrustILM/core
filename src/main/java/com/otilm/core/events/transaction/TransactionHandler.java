package com.otilm.core.events.transaction;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.function.Supplier;

@Component
public class TransactionHandler {

    @Transactional(propagation = Propagation.REQUIRED)
    public <T> T runInTransaction(Supplier<T> supplier) {
        return supplier.get();
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void runInNewTransaction(Runnable runnable) {
        runnable.run();
    }

    /**
     * Run {@code supplier} in a fresh, isolated transaction (suspending any ambient one) and
     * return its value. Commits on normal return; rolls back and rethrows on RuntimeException.
     * For callers that need to capture state computed inside the locked transaction (e.g. a
     * post-commit cleanup decision) rather than the void {@link #runInNewTransaction(Runnable)}.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public <T> T runInNewTransaction(Supplier<T> supplier) {
        return supplier.get();
    }
}
