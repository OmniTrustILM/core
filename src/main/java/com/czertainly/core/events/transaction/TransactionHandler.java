package com.czertainly.core.events.transaction;

import com.czertainly.api.exception.EventException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.Callable;

@Component
public class TransactionHandler {

    @Transactional(propagation = Propagation.REQUIRED)
    public <T> T runInTransaction(Callable<T> action) throws EventException { // NOSONAR: EventException is rethrown via multi-catch
        try {
            return action.call();
        } catch (RuntimeException | EventException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e); // NOSONAR: Callable.call() declares checked Exception; wrapping is intentional
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void runInNewTransaction(Runnable runnable) {
        runnable.run();
    }
}
